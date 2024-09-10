#include <dirent.h>              // 디렉토리 조작을 위한 함수들을 포함하는 헤더 파일
#include <errno.h>               // 오류 번호를 정의하는 헤더 파일
#include <fcntl.h>               // 파일 제어 옵션을 정의하는 헤더 파일
#include <glob.h>                // 파일 경로 패턴 매칭을 위한 함수들을 포함하는 헤더 파일
#include <inttypes.h>            // 정수형 데이터의 형식을 정의하는 헤더 파일
#include <poll.h>                // 파일 디스크립터의 이벤트 감지를 위한 헤더 파일
#include <pthread.h>             // POSIX 스레드를 위한 헤더 파일
#include <signal.h>              // 신호 처리를 위한 헤더 파일
#include <stdint.h>              // 고정 크기 정수형 타입을 정의하는 헤더 파일
#include <stdio.h>               // 표준 입출력 관련 함수들을 포함하는 헤더 파일
#include <stdlib.h>              // 일반적인 유틸리티 함수들을 포함하는 헤더 파일 (예: 메모리 할당, 난수 생성 등)
#include <sys/epoll.h>           // epoll 시스템 콜을 사용하기 위한 헤더 파일 (이벤트 감지)
#include <sys/ioctl.h>           // 입출력 제어 시스템 콜을 위한 헤더 파일
#include <sys/mman.h>            // 메모리 맵핑을 위한 헤더 파일
#include <sys/personality.h>     // 프로세스의 실행 환경 설정을 위한 헤더 파일
#include <sys/resource.h>        // 시스템 자원 제한을 설정하기 위한 헤더 파일
#include <sys/stat.h>            // 파일 상태 및 파일 종류 확인을 위한 헤더 파일
#include <sys/wait.h>            // 자식 프로세스 종료 상태를 기다리기 위한 헤더 파일
#include <unistd.h>              // 표준 심볼 상수 및 자료형 정의 (예: read, write 등의 시스템 콜)

#include "libmcount/mcount.h"    // 외부 라이브러리: mcount 함수 관련 헤더 파일 (프로파일링에 사용)
#include "uftrace.h"             // uftrace 관련 정의 및 함수 헤더 파일 (uftrace는 함수 호출 추적 도구)
#include "utils/filter.h"        // 필터링 유틸리티 관련 헤더 파일
#include "utils/kernel.h"        // 커널 관련 유틸리티 함수 헤더 파일
#include "utils/list.h"          // 리스트 유틸리티 관련 헤더 파일
#include "utils/perf.h"          // 성능 측정 관련 유틸리티 함수 헤더 파일
#include "utils/shmem.h"         // 공유 메모리 관련 유틸리티 함수 헤더 파일
#include "utils/symbol.h"        // 심볼 관련 유틸리티 함수 헤더 파일
#include "utils/utils.h"         // 일반적인 유틸리티 함수 헤더 파일

#ifndef EM_RISCV                 // 만약 EM_RISCV가 정의되지 않았으면
#define EM_RISCV 243             // EM_RISCV를 243으로 정의 (RISC-V 아키텍처에 해당하는 매크로 값)
#endif

#ifndef EFD_SEMAPHORE            // 만약 EFD_SEMAPHORE가 정의되지 않았으면
#define EFD_SEMAPHORE (1 << 0)   // EFD_SEMAPHORE를 1의 비트 왼쪽 이동으로 정의 (세마포어 플래그)
#endif

#define SHMEM_NAME_SIZE (64 - (int)sizeof(struct list_head)) 
// SHMEM_NAME_SIZE를 64에서 struct list_head의 크기를 뺀 값으로 정의 (공유 메모리 이름의 크기)

struct shmem_list {              // 공유 메모리 리스트를 위한 구조체 정의
    struct list_head list;       // 리스트 헤더 (링크드 리스트 구현을 위한 필드)
    char id[SHMEM_NAME_SIZE];    // 공유 메모리 이름을 저장할 배열
};

static LIST_HEAD(shmem_list_head);   // 공유 메모리 리스트의 리스트 헤더를 초기화 (정적 변수)
static LIST_HEAD(shmem_need_unlink); // 삭제가 필요한 공유 메모리의 리스트 헤더를 초기화 (정적 변수)

struct buf_list {                // 버퍼 리스트를 위한 구조체 정의
    struct list_head list;       // 리스트 헤더 (링크드 리스트 구현을 위한 필드)
    int tid;                     // 스레드 ID를 저장할 필드
    void *shmem_buf;             // 공유 메모리 버퍼를 가리키는 포인터
};
static LIST_HEAD(buf_free_list);          // 버퍼가 비어 있는 리스트의 리스트 헤더를 초기화
static LIST_HEAD(buf_write_list);         // 데이터를 쓰기 위한 버퍼 리스트의 리스트 헤더를 초기화

/* currently active writers */
static LIST_HEAD(writer_list);            // 현재 활성화된 작성자(Writer) 리스트의 리스트 헤더를 초기화

static pthread_mutex_t free_list_lock = PTHREAD_MUTEX_INITIALIZER;  // buf_free_list에 대한 뮤텍스 초기화
static pthread_mutex_t write_list_lock = PTHREAD_MUTEX_INITIALIZER; // buf_write_list에 대한 뮤텍스 초기화
static bool buf_done;                     // 버퍼 처리가 완료되었는지를 나타내는 불리언 변수
static int thread_ctl[2];                 // 스레드 제어를 위한 두 개의 파일 디스크립터 배열

static bool has_perf_event;               // 성능 이벤트가 있는지 여부를 나타내는 불리언 변수
static bool has_sched_event;              // 스케줄링 이벤트가 있는지 여부를 나타내는 불리언 변수
static bool finish_received;              // 종료 신호를 받았는지 여부를 나타내는 불리언 변수

// 빠른 libmcount를 사용할 수 있는지 확인하는 함수
static bool can_use_fast_libmcount(struct uftrace_opts *opts)
{
    if (debug)                            // 디버그 모드가 활성화되었으면 빠른 libmcount 사용 불가
        return false;
    if (opts->depth != MCOUNT_DEFAULT_DEPTH)  // 깊이가 기본값이 아니면 빠른 libmcount 사용 불가
        return false;
    // UFTRACE 관련 환경 변수가 설정되어 있으면 빠른 libmcount 사용 불가
    if (getenv("UFTRACE_FILTER") || getenv("UFTRACE_TRIGGER") || getenv("UFTRACE_ARGUMENT") ||
        getenv("UFTRACE_RETVAL") || getenv("UFTRACE_PATCH") || getenv("UFTRACE_SCRIPT") ||
        getenv("UFTRACE_AUTO_ARGS") || getenv("UFTRACE_WATCH") || getenv("UFTRACE_CALLER") ||
        getenv("UFTRACE_SIGNAL") || getenv("UFTRACE_AGENT") || getenv("UFTRACE_LOCATION"))
        return false;
    return true;                          // 위 조건이 모두 충족되지 않으면 빠른 libmcount 사용 가능
}

// 디버그 도메인 문자열을 생성하는 함수
static char *build_debug_domain_string(void)
{
    int i, d;
    static char domain[2 * DBG_DOMAIN_MAX + 1];  // 디버그 도메인 문자열을 저장할 배열

    for (i = 0, d = 0; d < DBG_DOMAIN_MAX; d++) {  // 디버그 도메인 순회
        if (dbg_domain[d]) {               // 디버그 도메인이 활성화되었으면
            domain[i++] = DBG_DOMAIN_STR[d];  // 도메인 문자열을 domain 배열에 추가
            domain[i++] = dbg_domain[d] + '0'; // 도메인 번호를 '0'에서 시작하는 문자로 변환하여 추가
        }
    }
    domain[i] = '\0';                     // 문자열 끝에 NULL 문자 추가

    return domain;                        // 생성된 디버그 도메인 문자열 반환
}

char *get_libmcount_path(struct uftrace_opts *opts)
{
    // libmcount 경로를 반환하는 함수. uftrace 옵션을 사용하여 어떤 libmcount 라이브러리를 사용할지 결정.
    
    char *libmcount, *lib = xmalloc(PATH_MAX);  // PATH_MAX 크기의 메모리를 할당받아 lib에 저장
    bool must_use_multi_thread = has_dependency(opts->exename, "libpthread.so.0");
    // 실행 파일이 pthread(멀티스레딩 라이브러리)와 의존성을 가지는지 확인하고 그 결과를 저장
    
    if (opts->nop) {  // nop 옵션이 설정되었으면
        libmcount = "libmcount-nop.so";  // nop 버전의 libmcount 라이브러리 선택
    }
    else if (opts->libmcount_single && !must_use_multi_thread) {
        // libmcount_single 옵션이 설정되었고 멀티스레드 의존성이 없을 때
        if (can_use_fast_libmcount(opts))
            libmcount = "libmcount-fast-single.so";  // 빠른 단일 스레드 버전 libmcount 선택
        else
            libmcount = "libmcount-single.so";  // 단일 스레드 버전 libmcount 선택
    }
    else {  // 그 외의 경우
        if (must_use_multi_thread && opts->libmcount_single)
            // 멀티스레드를 사용해야 하고 libmcount_single 옵션이 설정된 경우
            pr_dbg("--libmcount-single is off because it uses pthread\n");  
            // libmcount_single 옵션이 비활성화되었음을 디버그 메시지로 출력

        if (can_use_fast_libmcount(opts))
            libmcount = "libmcount-fast.so";  // 빠른 멀티스레드 버전 libmcount 선택
        else
            libmcount = "libmcount.so";  // 기본 멀티스레드 버전 libmcount 선택
    }

    if (opts->lib_path) {
        // 사용자가 lib_path를 지정한 경우 해당 경로에서 libmcount 파일을 찾음
        snprintf(lib, PATH_MAX, "%s/libmcount/%s", opts->lib_path, libmcount);
        // 지정된 경로에서 libmcount 파일을 찾도록 경로 문자열 생성

        if (access(lib, F_OK) == 0) {
            // libmcount 파일이 존재하면 그 경로를 반환
            return lib;
        }
        else if (errno == ENOENT) {
            // 파일이 존재하지 않으면 다시 경로를 조정하여 libmcount 파일을 찾음
            snprintf(lib, PATH_MAX, "%s/%s", opts->lib_path, libmcount);
            if (access(lib, F_OK) == 0)
                return lib;
        }
        free(lib);  // 경로가 존재하지 않으면 메모리 해제
        return NULL;  // 경로를 찾을 수 없으면 NULL 반환
    }

#ifdef INSTALL_LIB_PATH
    /* 설치 경로에서 libmcount 파일을 먼저 시도해봄 */
    snprintf(lib, PATH_MAX, "%s/%s", INSTALL_LIB_PATH, libmcount);
    if (access(lib, F_OK) == 0)
        return lib;  // 설치 경로에서 libmcount 파일이 존재하면 그 경로 반환
#endif

    strncpy(lib, libmcount, PATH_MAX);  // 기본적으로 libmcount 파일명을 lib에 복사
    return lib;  // libmcount 경로를 반환
}

void put_libmcount_path(char *libpath)
{
    // libmcount 경로 메모리를 해제하는 함수
    free(libpath);  // 전달받은 경로 메모리 해제
}
static void setup_child_environ(struct uftrace_opts *opts, int argc, char *argv[])
{
    // uftrace 옵션과 인수를 사용하여 자식 프로세스의 환경 변수를 설정하는 함수

    char buf[PATH_MAX];  // 경로 최대 길이 버퍼
    char *old_preload, *libpath;  // 기존 LD_PRELOAD 값과 libmcount 경로를 저장할 변수

#ifdef INSTALL_LIB_PATH
    if (!opts->lib_path) {  // 옵션에서 lib_path가 지정되지 않은 경우
        char *envbuf = getenv("LD_LIBRARY_PATH");  // 기존 LD_LIBRARY_PATH 환경 변수 값을 가져옴

        if (envbuf) {
            envbuf = xstrdup(envbuf);  // 기존 환경 변수를 복사
            libpath = strjoin(envbuf, INSTALL_LIB_PATH, ":");  // 새로운 경로 추가
            setenv("LD_LIBRARY_PATH", libpath, 1);  // LD_LIBRARY_PATH를 업데이트
            free(libpath);  // 메모리 해제
        } else {
            setenv("LD_LIBRARY_PATH", INSTALL_LIB_PATH, 1);  // INSTALL_LIB_PATH를 LD_LIBRARY_PATH로 설정
        }
    }
#endif

    // 다양한 uftrace 옵션들을 확인하고 해당하는 환경 변수를 설정
    if (opts->filter) {
        char *filter_str = uftrace_clear_kernel(opts->filter);  // 필터 문자열에서 커널 필터 제거

        if (filter_str) {
            setenv("UFTRACE_FILTER", filter_str, 1);  // UFTRACE_FILTER 환경 변수 설정
            free(filter_str);  // 메모리 해제
        }
    }

    if (opts->loc_filter) {
        char *loc_str = uftrace_clear_kernel(opts->loc_filter);  // 위치 필터에서 커널 필터 제거

        if (loc_str) {
            setenv("UFTRACE_LOCATION", loc_str, 1);  // UFTRACE_LOCATION 환경 변수 설정
            setenv("UFTRACE_SRCLINE", "1", 1);  // 소스 코드 라인 표시 활성화
            free(loc_str);  // 메모리 해제
        }
    }

    if (opts->trigger) {
        char *trigger_str = uftrace_clear_kernel(opts->trigger);  // 트리거에서 커널 필터 제거

        if (trigger_str) {
            setenv("UFTRACE_TRIGGER", trigger_str, 1);  // UFTRACE_TRIGGER 환경 변수 설정
            free(trigger_str);  // 메모리 해제
        }
    }

    if (opts->args) {
        char *arg_str = uftrace_clear_kernel(opts->args);  // 인수 필터에서 커널 필터 제거

        if (arg_str) {
            setenv("UFTRACE_ARGUMENT", arg_str, 1);  // UFTRACE_ARGUMENT 환경 변수 설정
            free(arg_str);  // 메모리 해제
        }
    }

    if (opts->retval) {
        char *retval_str = uftrace_clear_kernel(opts->retval);  // 반환값 필터에서 커널 필터 제거

        if (retval_str) {
            setenv("UFTRACE_RETVAL", retval_str, 1);  // UFTRACE_RETVAL 환경 변수 설정
            free(retval_str);  // 메모리 해제
        }
    }

    if (opts->auto_args)
        setenv("UFTRACE_AUTO_ARGS", "1", 1);  // 자동 인수 추적 활성화

    if (opts->patch) {
        char *patch_str = uftrace_clear_kernel(opts->patch);  // 패치 필터에서 커널 필터 제거

        if (patch_str) {
            setenv("UFTRACE_PATCH", patch_str, 1);  // UFTRACE_PATCH 환경 변수 설정
            free(patch_str);  // 메모리 해제
        }
    }

    if (opts->size_filter) {
        snprintf(buf, sizeof(buf), "%d", opts->size_filter);  // 크기 필터를 문자열로 변환
        setenv("UFTRACE_MIN_SIZE", buf, 1);  // UFTRACE_MIN_SIZE 환경 변수 설정
    }

    if (opts->event) {
        char *event_str = uftrace_clear_kernel(opts->event);  // 이벤트 필터에서 커널 필터 제거

        if (event_str) {
            setenv("UFTRACE_EVENT", event_str, 1);  // UFTRACE_EVENT 환경 변수 설정
            free(event_str);  // 메모리 해제
        }
    }

    if (opts->watch)
        setenv("UFTRACE_WATCH", opts->watch, 1);  // UFTRACE_WATCH 환경 변수 설정

    if (opts->depth != OPT_DEPTH_DEFAULT) {
        snprintf(buf, sizeof(buf), "%d", opts->depth);  // 추적 깊이를 문자열로 변환
        setenv("UFTRACE_DEPTH", buf, 1);  // UFTRACE_DEPTH 환경 변수 설정
    }

    if (opts->max_stack != OPT_RSTACK_DEFAULT) {
        snprintf(buf, sizeof(buf), "%d", opts->max_stack);  // 최대 스택 크기를 문자열로 변환
        setenv("UFTRACE_MAX_STACK", buf, 1);  // UFTRACE_MAX_STACK 환경 변수 설정
    }

    if (opts->threshold) {
        snprintf(buf, sizeof(buf), "%" PRIu64, opts->threshold);  // 임계값을 문자열로 변환
        setenv("UFTRACE_THRESHOLD", buf, 1);  // UFTRACE_THRESHOLD 환경 변수 설정
    }

    if (opts->caller) {
        char *caller_str = uftrace_clear_kernel(opts->caller);  // 호출자 필터에서 커널 필터 제거

        if (caller_str) {
            setenv("UFTRACE_CALLER", caller_str, 1);  // UFTRACE_CALLER 환경 변수 설정
            free(caller_str);  // 메모리 해제
        }
    }

    if (opts->libcall) {
        setenv("UFTRACE_PLTHOOK", "1", 1);  // 라이브러리 호출 후킹 활성화

        if (opts->want_bind_not) {
            setenv("LD_BIND_NOT", "1", 1);  // 심볼이 해석된 후 GOT/PLT 업데이트를 하지 않도록 설정
        }

        if (opts->nest_libcall)
            setenv("UFTRACE_NEST_LIBCALL", "1", 1);  // 중첩된 라이브러리 호출 허용
    }

    if (strcmp(opts->dirname, UFTRACE_DIR_NAME))
        setenv("UFTRACE_DIR", opts->dirname, 1);  // 디렉토리 경로를 UFTRACE_DIR로 설정

    if (opts->bufsize != SHMEM_BUFFER_SIZE) {
        snprintf(buf, sizeof(buf), "%lu", opts->bufsize);  // 버퍼 크기를 문자열로 변환
        setenv("UFTRACE_BUFFER", buf, 1);  // UFTRACE_BUFFER 환경 변수 설정
    }

    if (opts->logfile) {
        snprintf(buf, sizeof(buf), "%d", fileno(logfp));  // 로그 파일 디스크립터를 문자열로 변환
        setenv("UFTRACE_LOGFD", buf, 1);  // UFTRACE_LOGFD 환경 변수 설정
    }

    setenv("UFTRACE_SHMEM", "1", 1);  // 공유 메모리 사용 설정

    if (debug) {
        snprintf(buf, sizeof(buf), "%d", debug);  // 디버그 값을 문자열로 변환
        setenv("UFTRACE_DEBUG", buf, 1);  // UFTRACE_DEBUG 환경 변수 설정
        setenv("UFTRACE_DEBUG_DOMAIN", build_debug_domain_string(), 1);  // 디버그 도메인 문자열 설정
    }

    if (opts->trace == TRACE_STATE_OFF)
        setenv("UFTRACE_TRACE_OFF", "1", 1);  // 추적 비활성화 설정

    if (log_color == COLOR_ON) {
        snprintf(buf, sizeof(buf), "%d", log_color);  // 색상 설정을 문자열로 변환
        setenv("UFTRACE_COLOR", buf, 1);  // UFTRACE_COLOR 환경 변수 설정
    }

    snprintf(buf, sizeof(buf), "%d", demangler);  // 디망글러 설정을 문자열로 변환
    setenv("UFTRACE_DEMANGLE", buf, 1);  // UFTRACE_DEMANGLE 환경 변수 설정

    if ((opts->kernel || has_kernel_event(opts->event)) && check_kernel_pid_filter())
        setenv("UFTRACE_KERNEL_PID_UPDATE", "1", 1);  // 커널 PID 업데이트 설정

    if (opts->script_file)
        setenv("UFTRACE_SCRIPT", opts->script_file, 1);  // 스크립트 파일 설정

    if (opts->patt_type != PATT_REGEX)
        setenv("UFTRACE_PATTERN", get_filter_pattern(opts->patt_type), 1);  // 패턴 유형 설정

    if (opts->sig_trigger)
        setenv("UFTRACE_SIGNAL", opts->sig_trigger, 1);  // 신호 트리거 설정

    if (opts->srcline)
        setenv("UFTRACE_SRCLINE", "1", 1);  // 소스 코드 라인 표시 활성화

    if (opts->estimate_return)
        setenv("UFTRACE_ESTIMATE_RETURN", "1", 1);  // 반환값 추정 활성화

    if (opts->clock)
        setenv("UFTRACE_CLOCK", opts->clock, 1);  // 시계 유형 설정

    if (opts->with_syms)
        setenv("UFTRACE_SYMBOL_DIR", opts->with_syms, 1);  // 심볼 디렉토리 설정

    if (opts->agent)
        setenv("UFTRACE_AGENT", "1", 1);  // 에이전트 설정

    if (argc > 0) {
        // 전달된 인수가 있으면 각 인수를 환경 변수에 저장
        char *args = NULL;
        int i;

        for (i = 0; i < argc; i++)
            args = strjoin(args, argv[i], "\n");

        setenv("UFTRACE_ARGS", args, 1);  // UFTRACE_ARGS 환경 변수 설정
        free(args);  // 메모리 해제
    }

    /*
     * ----- 옵션 처리 끝 -----
     */

    libpath = get_libmcount_path(opts);  // libmcount 경로 가져오기
    if (libpath == NULL)
        pr_err_ns("uftrace could not find libmcount.so for record-tracing\n");  // libmcount를 찾지 못하면 오류 출력

    pr_dbg("using %s library for tracing\n", libpath);  // 추적에 사용할 libmcount 경로 출력

    old_preload = getenv("LD_PRELOAD");  // 기존 LD_PRELOAD 값 가져오기
    if (old_preload) {
        size_t len = strlen(libpath) + strlen(old_preload) + 2;
        char *preload = xmalloc(len);

        snprintf(preload, len, "%s:%s", libpath, old_preload);  // 기존 LD_PRELOAD에 libmcount 경로 추가
        setenv("LD_PRELOAD", preload, 1);  // LD_PRELOAD 환경 변수 설정
        free(preload);  // 메모리 해제
    } else {
        setenv("LD_PRELOAD", libpath, 1);  // LD_PRELOAD에 libmcount 경로 설정
    }

    put_libmcount_path(libpath);  // libmcount 경로 메모리 해제
    setenv("XRAY_OPTIONS", "patch_premain=false", 1);  // XRay 옵션 설정
    setenv("GLIBC_TUNABLES", "glibc.cpu.hwcaps=-IBT,-SHSTK", 1);  // GLIBC 조정 설정

    /* 디버그 정보 데몬 비활성화 */
    unsetenv("DEBUGINFOD_URLS");
}
static uint64_t calc_feat_mask(struct uftrace_opts *opts)
{
    // 주어진 uftrace 옵션에 따라 기능 마스크(feature mask)를 계산하는 함수
    uint64_t features = 0;  // 기능 마스크 변수
    char *buf = NULL;       // 파일 경로를 저장할 버퍼
    glob_t g;               // 파일 패턴 매칭을 위한 glob 구조체

    /* mcount 코드가 task 및 sid-XXX.map 파일을 생성 */
    features |= TASK_SESSION;  // TASK_SESSION 플래그 설정

    /* 심볼 파일이 상대 주소를 저장 */
    features |= SYM_REL_ADDR;  // SYM_REL_ADDR 플래그 설정

    /* mcount_max_stack 값을 저장 */
    features |= MAX_STACK;  // MAX_STACK 플래그 설정

    /* 자동 인수/반환값 스펙을 제공 */
    features |= AUTO_ARGS;  // AUTO_ARGS 플래그 설정

    if (has_perf_event)
        features |= PERF_EVENT;  // 성능 이벤트가 있으면 PERF_EVENT 플래그 설정

    if (opts->libcall)
        features |= PLTHOOK;  // 라이브러리 호출 후킹이 활성화되었으면 PLTHOOK 플래그 설정

    if (opts->kernel)
        features |= KERNEL;  // 커널 추적이 활성화되었으면 KERNEL 플래그 설정

    if (opts->args || opts->auto_args)
        features |= ARGUMENT;  // 인수 추적이 활성화되었으면 ARGUMENT 플래그 설정

    if (opts->retval || opts->auto_args)
        features |= RETVAL;  // 반환값 추적이 활성화되었으면 RETVAL 플래그 설정

    if (opts->event)
        features |= EVENT;  // 이벤트 추적이 활성화되었으면 EVENT 플래그 설정

    if (opts->estimate_return)
        features |= ESTIMATE_RETURN;  // 반환값 추정이 활성화되었으면 ESTIMATE_RETURN 플래그 설정

    /* 심볼 파일이 크기를 저장 */
    features |= SYM_SIZE;  // SYM_SIZE 플래그 설정

    xasprintf(&buf, "%s/*.dbg", opts->dirname);  // 옵션에서 디버그 파일 경로 문자열 생성
    if (glob(buf, GLOB_NOSORT, NULL, &g) != GLOB_NOMATCH)
        features |= DEBUG_INFO;  // 디버그 파일이 있으면 DEBUG_INFO 플래그 설정

    globfree(&g);  // glob로 할당된 메모리 해제
    free(buf);     // 경로 버퍼 해제

    return features;  // 계산된 기능 마스크 반환
}

int fill_file_header(struct uftrace_opts *opts, int status, struct rusage *rusage,
                     char *elapsed_time)
{
    // uftrace 파일 헤더를 채우고 저장하는 함수
    int fd, efd;  // 파일 디스크립터
    int ret = -1;  // 반환값, 기본적으로 실패(-1)로 초기화
    char *filename = NULL;  // 파일명을 저장할 변수
    struct uftrace_file_header hdr;  // uftrace 파일 헤더 구조체
    char elf_ident[EI_NIDENT];  // ELF 파일의 식별자를 저장할 배열

    xasprintf(&filename, "%s/info", opts->dirname);  // info 파일 경로 생성
    pr_dbg3("fill header (metadata) info in %s\n", filename);  // 디버그 메시지 출력

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);  // info 파일을 쓰기 모드로 엶
    if (fd < 0)
        pr_err("cannot open info file");  // 파일을 열 수 없으면 오류 출력

    efd = open(opts->exename, O_RDONLY);  // 실행 파일을 읽기 모드로 엶
    if (efd < 0)
        goto close_fd;  // 실행 파일을 열 수 없으면 파일 닫기로 이동

    if (read(efd, elf_ident, sizeof(elf_ident)) < 0)
        goto close_efd;  // 실행 파일에서 ELF 식별자를 읽을 수 없으면 파일 닫기로 이동

    strncpy(hdr.magic, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN);  // uftrace 매직 문자열 복사
    hdr.version = UFTRACE_FILE_VERSION;  // 파일 버전 설정
    hdr.header_size = sizeof(hdr);  // 헤더 크기 설정
    hdr.endian = elf_ident[EI_DATA];  // ELF 파일의 엔디언 정보 설정
    hdr.elf_class = elf_ident[EI_CLASS];  // ELF 클래스 설정 (32비트 또는 64비트)
    hdr.feat_mask = calc_feat_mask(opts);  // 기능 마스크 계산 및 설정
    hdr.info_mask = 0;  // 정보 마스크 초기화
    hdr.max_stack = opts->max_stack;  // 최대 스택 크기 설정
    hdr.unused1 = 0;  // 사용되지 않는 필드 초기화
    hdr.unused2 = 0;  // 사용되지 않는 필드 초기화

    if (write(fd, &hdr, sizeof(hdr)) != (int)sizeof(hdr))
        pr_err("writing header info failed");  // 헤더 쓰기에 실패하면 오류 출력

    fill_uftrace_info(&hdr.info_mask, fd, opts, status, rusage, elapsed_time);  // uftrace 정보 추가

try_write:
    ret = pwrite(fd, &hdr, sizeof(hdr), 0);  // 파일에 헤더 정보를 기록
    if (ret != (int)sizeof(hdr)) {  // 쓰기 실패 시
        static int retry = 0;  // 재시도 횟수 추적

        if (ret > 0 && retry++ < 3)
            goto try_write;  // 최대 3번까지 재시도

        pr_dbg("writing header info failed.\n");  // 쓰기 실패 디버그 메시지 출력
        goto close_efd;  // 파일 닫기로 이동
    }

    ret = 0;  // 성공적으로 헤더 기록 시 반환값 0으로 설정

close_efd:
    close(efd);  // 실행 파일 디스크립터 닫기
close_fd:
    close(fd);  // info 파일 디스크립터 닫기
    free(filename);  // 파일명 메모리 해제

    return ret;  // 결과 반환 (성공 시 0, 실패 시 -1)
}

/* NUL 문자를 포함한 메시지 ID의 크기 정의 */
#define MSG_ID_SIZE 36

static void parse_msg_id(char *id, uint64_t *sid, int *tid, int *seq)
{
    // 메시지 ID를 파싱하는 함수. 메시지 ID는 "/uftrace-SESSION-TID-SEQ" 형식으로 제공됨.
    uint64_t _sid;  // 세션 ID를 저장할 임시 변수
    unsigned _tid;  // 스레드 ID를 저장할 임시 변수
    unsigned _seq;  // 시퀀스 번호를 저장할 임시 변수

    /*
     * 메시지 ID가 "/uftrace-SESSION-TID-SEQ" 형식으로 주어졌을 때 이를 파싱.
     * SCNx64는 16진수로 64비트 정수를 읽는 포맷 지정자.
     */
    if (sscanf(id, "/uftrace-%016" SCNx64 "-%u-%03u", &_sid, &_tid, &_seq) != 3)
        pr_err("parse msg id failed");  // 파싱이 실패하면 오류 출력

    // 세션 ID, 스레드 ID, 시퀀스 번호를 각각 저장
    if (sid)
        *sid = _sid;  // 파싱한 세션 ID를 sid에 저장
    if (tid)
        *tid = _tid;  // 파싱한 스레드 ID를 tid에 저장
    if (seq)
        *seq = _seq;  // 파싱한 시퀀스 번호를 seq에 저장
}

static char *make_disk_name(const char *dirname, int tid)
{
    // 디스크에 저장할 파일 이름을 생성하는 함수
    char *filename = NULL;

    // 경로 문자열을 생성하여 filename에 저장
    xasprintf(&filename, "%s/%d.dat", dirname, tid);  // "dirname/tid.dat" 형식으로 파일명 생성

    return filename;  // 생성된 파일명 반환
}

static void write_buffer_file(const char *dirname, struct buf_list *buf)
{
    // 버퍼 데이터를 파일에 기록하는 함수
    int fd;  // 파일 디스크립터
    char *filename;  // 파일 이름을 저장할 변수
    struct mcount_shmem_buffer *shmbuf = buf->shmem_buf;  // 공유 메모리 버퍼

    filename = make_disk_name(dirname, buf->tid);  // 버퍼의 스레드 ID를 사용해 파일 이름 생성
    fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);  // 파일을 쓰기 모드로 열거나 생성, 추가 모드로 설정
    if (fd < 0)
        pr_err("open disk file");  // 파일을 열 수 없으면 오류 출력

    // 공유 메모리 버퍼 데이터를 파일에 기록
    if (write_all(fd, shmbuf->data, shmbuf->size) < 0)
        pr_err("write shmem buffer");  // 기록 실패 시 오류 출력

    close(fd);  // 파일 닫기
    free(filename);  // 파일명 메모리 해제
}

static void write_buffer(struct buf_list *buf, struct uftrace_opts *opts, int sock)
{
    // 버퍼 데이터를 파일 또는 네트워크 소켓으로 전송하는 함수
    struct mcount_shmem_buffer *shmbuf = buf->shmem_buf;  // 공유 메모리 버퍼

    if (!opts->host)  // 호스트가 지정되지 않았으면
        write_buffer_file(opts->dirname, buf);  // 버퍼 데이터를 파일에 기록
    else
        send_trace_data(sock, buf->tid, shmbuf->data, shmbuf->size);  // 네트워크 소켓으로 버퍼 데이터를 전송

    shmbuf->size = 0;  // 버퍼 사이즈를 0으로 초기화
}

struct writer_arg {
    // 작성자(writer) 스레드의 인수 구조체
    struct list_head list;                   // 리스트 헤더 (링크드 리스트로 사용)
    struct list_head bufs;                   // 버퍼 리스트 헤더
    struct uftrace_opts *opts;               // uftrace 옵션 포인터
    struct uftrace_kernel_writer *kern;      // 커널 추적을 위한 작성자 구조체 포인터
    struct uftrace_perf_writer *perf;        // 성능 추적을 위한 작성자 구조체 포인터
    int sock;                                // 네트워크 소켓 파일 디스크립터
    int idx;                                 // 작성자의 인덱스
    int tid;                                 // 스레드 ID
    int nr_cpu;                              // 사용 중인 CPU의 개수
    int cpus[];                              // CPU 목록 (가변 길이 배열)
};

static void write_buf_list(struct list_head *buf_head, struct uftrace_opts *opts,
                           struct writer_arg *warg)
{
    // 버퍼 리스트의 내용을 파일 또는 네트워크로 쓰는 함수
    struct buf_list *buf;

    list_for_each_entry(buf, buf_head, list) {  // buf_head에 연결된 모든 버퍼에 대해 반복
        struct mcount_shmem_buffer *shmbuf = buf->shmem_buf;

        write_buffer(buf, opts, warg->sock);  // 버퍼 데이터를 파일 또는 소켓으로 전송

        /*
         * 이제 공유 메모리 버퍼의 모든 내용을 소비했으므로, mcount가 재사용할 수 있도록 설정.
         * get_new_shmem_buffer()와 쌍을 이룸.
         */
        __sync_synchronize();  // 메모리 배리어 사용 (메모리 동기화)
        shmbuf->flag = SHMEM_FL_WRITTEN;  // 버퍼가 작성되었음을 나타내는 플래그 설정

        munmap(shmbuf, opts->bufsize);  // 공유 메모리 버퍼를 메모리에서 해제
        buf->shmem_buf = NULL;  // 버퍼의 포인터를 NULL로 설정
    }

    // free_list_lock 뮤텍스를 사용하여 버퍼를 해제 리스트로 이동
    pthread_mutex_lock(&free_list_lock);  // 뮤텍스 잠금
    while (!list_empty(buf_head)) {  // 버퍼 리스트가 비어 있지 않은 동안
        struct list_head *l = buf_head->next;  // 다음 버퍼를 가져옴
        list_move(l, &buf_free_list);  // 버퍼를 비어 있는 버퍼 리스트로 이동
    }
    pthread_mutex_unlock(&free_list_lock);  // 뮤텍스 잠금 해제
}

static int setup_pollfd(struct pollfd **pollfd, struct writer_arg *warg, bool setup_perf,
                        bool setup_kernel)
{
    // pollfd 배열을 설정하는 함수. 성능 및 커널 추적을 위한 파일 디스크립터 추가.
    int nr_poll = 1;  // 기본적으로 thread_ctl[0]에 대한 폴링
    struct pollfd *p;
    int i;

    if (setup_perf)  // 성능 추적이 활성화된 경우
        nr_poll += warg->nr_cpu;  // CPU 수만큼 폴링할 항목 추가
    if (setup_kernel)  // 커널 추적이 활성화된 경우
        nr_poll += warg->nr_cpu;  // CPU 수만큼 폴링할 항목 추가

    p = xcalloc(nr_poll, sizeof(*p));  // pollfd 배열을 할당

    p[0].fd = thread_ctl[0];  // 첫 번째 항목은 thread_ctl[0]
    p[0].events = POLLIN;  // 읽기 이벤트(POLLIN) 설정
    nr_poll = 1;

    if (setup_perf) {  // 성능 추적 설정
        for (i = 0; i < warg->nr_cpu; i++) {
            p[i + nr_poll].fd = warg->perf->event_fd[warg->cpus[i]];  // CPU별 성능 이벤트 FD
            p[i + nr_poll].events = POLLIN;  // 읽기 이벤트 설정
        }
        nr_poll += warg->nr_cpu;  // 폴링할 CPU 개수만큼 증가
    }

    if (setup_kernel) {  // 커널 추적 설정
        for (i = 0; i < warg->nr_cpu; i++) {
            p[i + nr_poll].fd = warg->kern->traces[warg->cpus[i]];  // CPU별 커널 추적 FD
            p[i + nr_poll].events = POLLIN;  // 읽기 이벤트 설정
        }
        nr_poll += warg->nr_cpu;  // 폴링할 CPU 개수만큼 증가
    }

    *pollfd = p;  // pollfd 포인터 설정
    return nr_poll;  // 설정된 poll 항목의 개수 반환
}

static bool handle_pollfd(struct pollfd *pollfd, struct writer_arg *warg, bool trace_task,
                          bool trace_perf, bool trace_kernel, int timeout)
{
    // poll된 이벤트를 처리하는 함수
    int start = trace_task ? 0 : 1;  // trace_task가 활성화된 경우 시작 인덱스는 0, 아니면 1
    int nr_poll = trace_task ? 1 : 0;  // trace_task에 대한 폴링 여부 결정
    bool check_task = false;  // trace_task에서 폴링된 데이터를 처리했는지 여부
    int i;

    if (trace_perf)
        nr_poll += warg->nr_cpu;  // 성능 추적이 활성화된 경우 CPU 개수만큼 폴링 항목 증가
    if (trace_kernel)
        nr_poll += warg->nr_cpu;  // 커널 추적이 활성화된 경우 CPU 개수만큼 폴링 항목 증가

    if (poll(&pollfd[start], nr_poll, timeout) < 0)
        return false;  // poll 함수 호출 실패 시 false 반환

    for (i = start; i < nr_poll; i++) {
        if (!(pollfd[i].revents & POLLIN))  // 폴링된 이벤트가 없으면 건너뜀
            continue;

        if (i == 0)
            check_task = true;  // task 이벤트가 감지되면 check_task를 true로 설정
        else if (trace_perf && i < (warg->nr_cpu + 1)) {
            record_perf_data(warg->perf, warg->cpus[i - 1], warg->sock);  // 성능 데이터 기록
        }
        else if (trace_kernel) {
            int idx = i - (nr_poll - warg->nr_cpu);  // CPU 인덱스를 계산
            record_kernel_trace_pipe(warg->kern, warg->cpus[idx], warg->sock);  // 커널 추적 기록
        }
    }

    return check_task;  // task 이벤트가 처리되었는지 여부 반환
}

static void finish_pollfd(struct pollfd *pollfd)
{
    // pollfd 메모리를 해제하는 함수
    free(pollfd);  // pollfd 배열 해제
}
void *writer_thread(void *arg)
{
    // 작성자(writer) 스레드의 진입점 함수
    struct buf_list *buf, *pos;  // 버퍼 리스트를 가리키는 포인터
    struct writer_arg *warg = arg;  // 스레드 인수로 전달된 writer_arg 구조체 포인터
    struct uftrace_opts *opts = warg->opts;  // uftrace 옵션
    struct pollfd *pollfd;  // 폴링 파일 디스크립터
    int i, dummy;  // 반복 변수 및 임시 변수
    sigset_t sigset;  // 시그널 세트를 저장할 변수

    // 현재 스레드의 이름을 "WriterThread"로 설정
    pthread_setname_np(pthread_self(), "WriterThread");

    if (opts->rt_prio) {
        // 실시간 우선순위가 설정된 경우 스케줄러 우선순위 설정
        struct sched_param param = {
            .sched_priority = opts->rt_prio,  // 옵션에서 설정한 우선순위로 스케줄링 파라미터 설정
        };

        if (sched_setscheduler(0, SCHED_FIFO, &param) < 0)
            pr_warn("set scheduling param failed\n");  // 스케줄러 설정에 실패하면 경고 메시지 출력
    }

    // 모든 시그널을 차단 (실시간 스레드는 특정 시그널을 처리하지 않음)
    sigfillset(&sigset);  
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);  // 시그널 마스크 설정

    // pollfd 설정 (성능 및 커널 추적을 위한 파일 디스크립터 설정)
    setup_pollfd(&pollfd, warg, has_perf_event, opts->kernel);

    pr_dbg2("start writer thread %d\n", warg->idx);  // 디버그 메시지: 작성자 스레드 시작

    while (!buf_done) {  // 버퍼 작업이 완료될 때까지 반복
        LIST_HEAD(head);  // 임시 리스트 헤더 생성 (버퍼 리스트 저장)
        bool check_list = false;  // 버퍼를 처리할지 여부

        // poll된 파일 디스크립터를 처리하여 이벤트를 확인
        check_list = handle_pollfd(pollfd, warg, true, has_perf_event, opts->kernel, 1000);
        if (!check_list)
            continue;  // 처리할 리스트가 없으면 다음 반복으로 이동

        // thread_ctl[0]에서 데이터를 읽음 (쓰레드 제어용)
        if (read(thread_ctl[0], &dummy, sizeof(dummy)) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;  // 읽기 오류가 일시적인 경우 반복문을 계속 실행
            break;  // 그 외의 오류 발생 시 루프 종료
        }

        // write_list_lock 뮤텍스 잠금
        pthread_mutex_lock(&write_list_lock);

        if (!list_empty(&buf_write_list)) {
            // 버퍼 리스트에서 처리되지 않은 첫 번째 버퍼를 가져옴
            buf = list_first_entry(&buf_write_list, struct buf_list, list);
            list_move(&buf->list, &head);  // 해당 버퍼를 임시 리스트로 이동

            warg->tid = buf->tid;  // 해당 버퍼의 스레드 ID를 저장
            list_add(&warg->list, &writer_list);  // 작성자 리스트에 추가
        }

        // 같은 스레드 ID를 가진 모든 버퍼를 임시 리스트로 이동
        list_for_each_entry_safe(buf, pos, &buf_write_list, list) {
            if (buf->tid == warg->tid)
                list_move_tail(&buf->list, &head);  // tail에 추가하여 리스트의 순서 유지
        }

        pthread_mutex_unlock(&write_list_lock);  // 뮤텍스 잠금 해제

        while (!list_empty(&head)) {  // 임시 리스트에 있는 버퍼들을 처리
            write_buf_list(&head, opts, warg);  // 버퍼 데이터를 파일이나 네트워크로 전송

            pthread_mutex_lock(&write_list_lock);  // 다시 뮤텍스 잠금
            // warg에 버퍼가 직접 전송되었는지 확인하고 이를 임시 리스트로 병합
            list_splice_tail_init(&warg->bufs, &head);

            if (list_empty(&head)) {
                // 모든 버퍼 처리가 끝나면 해당 스레드 ID를 -1로 설정하고 리스트에서 제거
                warg->tid = -1;
                list_del_init(&warg->list);
            }
            pthread_mutex_unlock(&write_list_lock);  // 뮤텍스 잠금 해제

            if (!has_perf_event && !opts->kernel)
                continue;  // 성능 이벤트와 커널 추적이 없으면 다음 반복으로 이동

            // 폴링된 파일 디스크립터 이벤트를 다시 처리
            handle_pollfd(pollfd, warg, false, has_perf_event, opts->kernel, 0);
        }
    }

    pr_dbg2("stop writer thread %d\n", warg->idx);  // 디버그 메시지: 작성자 스레드 종료

    if (has_perf_event) {
        // 성능 이벤트가 활성화된 경우 각 CPU에서 성능 데이터를 기록
        for (i = 0; i < warg->nr_cpu; i++)
            record_perf_data(warg->perf, warg->cpus[i], warg->sock);
    }

    // pollfd 정리 및 메모리 해제
    finish_pollfd(pollfd);
    free(warg);  // warg 메모리 해제
    return NULL;  // 스레드 종료
}

static struct buf_list *make_write_buffer(void)
{
    // 버퍼 리스트 항목을 생성하는 함수
    struct buf_list *buf;

    buf = malloc(sizeof(*buf));  // buf_list 크기만큼 메모리 할당
    if (buf == NULL)
        return NULL;  // 메모리 할당 실패 시 NULL 반환

    INIT_LIST_HEAD(&buf->list);  // 리스트 헤더 초기화

    return buf;  // 생성된 buf_list 반환
}

static void copy_to_buffer(struct mcount_shmem_buffer *shm, char *sess_id)
{
    // 공유 메모리 버퍼를 적절한 작성자 스레드의 버퍼 리스트에 복사하는 함수
    struct buf_list *buf = NULL;  // 버퍼 리스트 구조체 포인터
    struct writer_arg *writer;    // 작성자 스레드 구조체 포인터

    // 빈 버퍼 리스트에서 사용 가능한 버퍼를 가져옴
    pthread_mutex_lock(&free_list_lock);  // free_list_lock 뮤텍스 잠금
    if (!list_empty(&buf_free_list)) {  // 버퍼가 남아 있으면
        buf = list_first_entry(&buf_free_list, struct buf_list, list);  // 첫 번째 버퍼 가져오기
        list_del(&buf->list);  // 버퍼를 빈 버퍼 리스트에서 제거
    }
    pthread_mutex_unlock(&free_list_lock);  // 뮤텍스 잠금 해제

    if (buf == NULL) {
        // 사용 가능한 버퍼가 없으면 새로운 버퍼를 생성
        buf = make_write_buffer();  // 새로운 버퍼 생성
        if (buf == NULL)  // 메모리 할당 실패 시 오류 출력
            pr_err_ns("not enough memory!\n");

        pr_dbg3("make a new write buffer\n");  // 새로운 버퍼 생성 디버그 메시지 출력
    }

    buf->shmem_buf = shm;  // 버퍼에 공유 메모리 포인터 설정
    parse_msg_id(sess_id, NULL, &buf->tid, NULL);  // 세션 ID를 통해 스레드 ID를 파싱하여 저장

    // 버퍼를 작성자 스레드에 추가
    pthread_mutex_lock(&write_list_lock);  // write_list_lock 뮤텍스 잠금
    list_for_each_entry(writer, &writer_list, list) {  // 작성자 리스트에서 일치하는 스레드 ID 탐색
        if (buf->tid == writer->tid) {
            // 일치하는 작성자 스레드가 있으면 버퍼를 해당 작성자에 직접 전달
            list_add_tail(&buf->list, &writer->bufs);  // 버퍼를 작성자의 버퍼 리스트에 추가
            break;
        }
    }
    if (list_no_entry(writer, &writer_list, list)) {
        // 일치하는 작성자가 없으면, 버퍼를 전역 쓰기 리스트에 추가하고 작성자 스레드를 알림
        int kick = 1;

        list_add_tail(&buf->list, &buf_write_list);  // 버퍼를 전역 쓰기 리스트에 추가
        if (write(thread_ctl[1], &kick, sizeof(kick)) < 0 && !buf_done)  // 작성자 스레드를 깨움
            pr_err("copying to buffer failed");  // 실패 시 오류 출력
    }
    pthread_mutex_unlock(&write_list_lock);  // 뮤텍스 잠금 해제
}

static void record_mmap_file(const char *dirname, char *sess_id, int bufsize)
{
    // 공유 메모리에서 데이터를 읽고 기록하는 함수
    int fd;  // 파일 디스크립터
    struct shmem_list *sl;  // 공유 메모리 리스트 항목 포인터
    struct mcount_shmem_buffer *shmem_buf;  // 공유 메모리 버퍼 포인터

    // 공유 메모리 파일을 읽기/쓰기 모드로 엶
    fd = uftrace_shmem_open(sess_id, O_RDWR, 0600);
    if (fd < 0) {
        pr_dbg("open shmem buffer failed: %s: %m\n", sess_id);  // 파일 열기에 실패하면 디버그 메시지 출력
        return;
    }

    // 공유 메모리 파일을 메모리에 매핑
    shmem_buf = mmap(NULL, bufsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shmem_buf == MAP_FAILED)  // 매핑 실패 시 오류 출력
        pr_err("mmap shmem buffer");

    close(fd);  // 파일 디스크립터 닫기

    if (shmem_buf->flag & SHMEM_FL_RECORDING) {  // 녹화 중인 공유 메모리 버퍼인지 확인
        if (shmem_buf->flag & SHMEM_FL_NEW) {  // 새로운 공유 메모리 버퍼인지 확인
            bool found = false;

            // 삭제 대기 중인 공유 메모리 리스트에서 해당 버퍼가 있는지 확인
            if (!list_empty(&shmem_need_unlink)) {
                sl = list_last_entry(&shmem_need_unlink, struct shmem_list, list);

                // "uftrace-<session id>-" 문자열 길이인 25 바이트를 기준으로 세션 ID 비교
                if (!strncmp(sl->id, sess_id, 25))
                    found = true;
            }

            if (!found) {
                // 해당하는 공유 메모리 버퍼가 없으면 새로 추가
                sl = xmalloc(sizeof(*sl));  // 메모리 할당
                memcpy(sl->id, sess_id, sizeof(sl->id));  // 세션 ID 복사

                // 공유 메모리 리스트에 새 항목 추가
                list_add_tail(&sl->list, &shmem_need_unlink);
            }
        }

        if (shmem_buf->size) {
            // 공유 메모리 버퍼에 데이터가 있으면 버퍼를 작성자 스레드로 복사
            copy_to_buffer(shmem_buf, sess_id);
            return;
        }
    }

    // 매핑 해제
    munmap(shmem_buf, bufsize);
}

static void stop_all_writers(void)
{
    // 모든 작성자 스레드를 중지시키는 함수
    buf_done = true;  // 버퍼 처리가 완료되었음을 나타내는 플래그 설정
    close(thread_ctl[1]);  // 스레드 제어용 파일 디스크립터 닫기
    thread_ctl[1] = -1;  // 파일 디스크립터를 비활성화
}

static void record_remaining_buffer(struct uftrace_opts *opts, int sock)
{
    // 작성자 스레드가 모두 종료된 후, 남아있는 버퍼를 기록하는 함수
    struct buf_list *buf;

    /* 작성자 스레드가 모두 종료된 상태이므로, 락(lock)이 필요하지 않음 */
    while (!list_empty(&buf_write_list)) {  // 버퍼가 남아 있을 때까지 반복
        buf = list_first_entry(&buf_write_list, struct buf_list, list);  // 첫 번째 버퍼 가져오기
        write_buffer(buf, opts, sock);  // 버퍼 내용을 파일이나 네트워크로 기록
        munmap(buf->shmem_buf, opts->bufsize);  // 버퍼의 공유 메모리를 해제

        list_del(&buf->list);  // 버퍼를 리스트에서 제거
        free(buf);  // 버퍼 메모리 해제
    }

    // 남아있는 빈 버퍼 리스트 처리
    while (!list_empty(&buf_free_list)) {  // 빈 버퍼가 남아 있을 때까지 반복
        buf = list_first_entry(&buf_free_list, struct buf_list, list);  // 첫 번째 빈 버퍼 가져오기

        list_del(&buf->list);  // 빈 버퍼를 리스트에서 제거
        free(buf);  // 빈 버퍼 메모리 해제
    }
}

static void flush_shmem_list(const char *dirname, int bufsize)
{
    // 비정상 종료로 인해 남아있는 공유 메모리 리스트를 플러시(기록)하는 함수
    struct shmem_list *sl, *tmp;

    /* 비정상 종료로 인해 남아있는 리스트를 처리 */
    list_for_each_entry_safe(sl, tmp, &shmem_list_head, list) {
        pr_dbg("flushing %s\n", sl->id);  // 디버그 메시지 출력

        list_del(&sl->list);  // 리스트에서 항목을 제거
        record_mmap_file(dirname, sl->id, bufsize);  // 남아있는 공유 메모리 버퍼를 기록
        free(sl);  // 리스트 항목 메모리 해제
    }
}

static char shmem_session[20];  // 공유 메모리 세션 ID 저장용 버퍼

static int filter_shmem(const struct dirent *de)
{
    // 세션 ID를 비교하여 특정 세션에 해당하는 공유 메모리만 필터링하는 함수
    /* "uftrace-" 부분 이후의 세션 ID를 비교 */
    return !memcmp(&de->d_name[8], shmem_session, 16);  // 세션 ID의 16바이트를 비교
}

static void unlink_shmem_list(void)
{
    // 더 이상 사용되지 않는 공유 메모리 리스트 항목을 언링크(unlink)하는 함수
    struct shmem_list *sl, *tmp;

    /* 사용되지 않는 공유 메모리 리스트를 언링크 */
    list_for_each_entry_safe(sl, tmp, &shmem_need_unlink, list) {
        char sid[128];  // 공유 메모리 파일 경로 저장용 버퍼
        struct dirent **shmem_bufs;  // 디렉토리 항목을 저장할 배열
        int i, num;  // 반복 변수 및 디렉토리 항목 수

        list_del(&sl->list);  // 리스트에서 항목을 제거

        // 세션 ID를 파싱하여 shmem_session에 저장
        sscanf(sl->id, "/uftrace-%[^-]-%*d-%*d", shmem_session);
        pr_dbg2("unlink for session: %s\n", shmem_session);  // 디버그 메시지 출력

        // 공유 메모리 파일을 필터링하여 해당 세션에 대한 파일 목록을 가져옴
        num = scandir(uftrace_shmem_root(), &shmem_bufs, filter_shmem, alphasort);
        for (i = 0; i < num; i++) {
            // 공유 메모리 파일을 삭제
            sid[0] = '/';
            memcpy(&sid[1], shmem_bufs[i]->d_name, MSG_ID_SIZE);  // 파일명 복사
            pr_dbg3("unlink %s\n", sid);  // 디버그 메시지 출력
            uftrace_shmem_unlink(sid);  // 공유 메모리 파일 언링크
            free(shmem_bufs[i]);  // 디렉토리 항목 메모리 해제
        }

        free(shmem_bufs);  // 공유 메모리 버퍼 배열 메모리 해제
        free(sl);  // 공유 메모리 리스트 항목 메모리 해제
    }
}
static void flush_old_shmem(const char *dirname, int tid, int bufsize)
{
    // 비정상 종료로 인해 남아있는 특정 스레드 ID에 대한 공유 메모리 데이터를 플러시하는 함수
    struct shmem_list *sl;

    /* 비정상 종료로 인해 남아있는 공유 메모리 리스트를 처리 */
    list_for_each_entry(sl, &shmem_list_head, list) {  // 공유 메모리 리스트의 모든 항목을 순회
        int sl_tid;

        // 공유 메모리 ID에서 스레드 ID(tid)를 파싱
        sscanf(sl->id, "/uftrace-%*x-%d-%*d", &sl_tid);

        if (tid == sl_tid) {  // 현재 항목의 스레드 ID가 주어진 tid와 일치하면
            pr_dbg3("flushing %s\n", sl->id);  // 디버그 메시지 출력

            list_del(&sl->list);  // 리스트에서 해당 항목 제거
            record_mmap_file(dirname, sl->id, bufsize);  // 남아있는 공유 메모리 버퍼를 기록
            free(sl);  // 메모리 해제
            return;  // 함수 종료
        }
    }
}

static int shmem_lost_count;  // 공유 메모리를 잃어버린 횟수를 저장하는 전역 변수

struct tid_list {
    // 스레드 정보를 저장하는 리스트 항목 구조체
    struct list_head list;  // 리스트 헤더 (링크드 리스트로 사용)
    int pid;                // 프로세스 ID
    int tid;                // 스레드 ID
    bool exited;            // 스레드가 종료되었는지 여부
};

static LIST_HEAD(tid_list_head);  // 스레드 리스트의 헤더 초기화

static bool child_exited;  // 자식 프로세스가 종료되었는지 여부를 나타내는 플래그

static void sigchld_handler(int sig, siginfo_t *sainfo, void *context)
{
    // SIGCHLD 시그널 핸들러. 자식 프로세스가 종료되었을 때 호출됨.
    int tid = sainfo->si_pid;  // 종료된 프로세스의 ID를 가져옴
    struct tid_list *tl;

    // 스레드 리스트에서 종료된 스레드를 찾아서 처리
    list_for_each_entry(tl, &tid_list_head, list) {
        if (tl->tid == tid) {  // 리스트에서 종료된 스레드 ID와 일치하는 항목을 찾음
            tl->exited = true;  // 해당 스레드가 종료되었음을 표시
            break;  // 더 이상 탐색하지 않고 종료
        }
    }

    child_exited = true;  // 자식 프로세스가 종료되었음을 나타내는 플래그 설정
}

static void add_tid_list(int pid, int tid)
{
    // 새로운 스레드 항목을 생성하고 리스트에 추가하는 함수
    struct tid_list *tl;

    tl = xmalloc(sizeof(*tl));  // 스레드 리스트 항목에 대한 메모리 할당

    tl->pid = pid;  // 프로세스 ID 설정
    tl->tid = tid;  // 스레드 ID 설정
    tl->exited = false;  // 스레드가 아직 종료되지 않았음을 설정

    /* 스레드 리스트에 항목 추가 */
    list_add(&tl->list, &tid_list_head);  // 새로 생성한 항목을 스레드 리스트에 추가
}
static void free_tid_list(void)
{
    // 스레드 리스트의 모든 항목을 해제하는 함수
    struct tid_list *tl, *tmp;

    // tid_list_head 리스트의 모든 항목을 안전하게 순회하며 메모리 해제
    list_for_each_entry_safe(tl, tmp, &tid_list_head, list) {
        list_del(&tl->list);  // 리스트에서 항목 제거
        free(tl);  // 항목에 할당된 메모리 해제
    }
}

static bool check_tid_list(void)
{
    // 스레드 리스트를 검사하여 모든 스레드가 종료되었는지 확인하는 함수
    struct tid_list *tl;  // 스레드 리스트 항목 포인터
    char buf[128];  // 프로세스 파일 경로 저장용 버퍼

    // tid_list_head 리스트의 모든 항목을 순회하며 각 스레드의 상태를 확인
    list_for_each_entry(tl, &tid_list_head, list) {
        int fd, len;  // 파일 디스크립터 및 읽기 길이
        char state;  // 스레드 상태를 저장할 변수 ('Z'는 좀비 상태)
        char line[PATH_MAX];  // 읽은 내용을 저장할 버퍼

        if (tl->exited || tl->tid < 0)  // 스레드가 이미 종료되었거나 유효하지 않으면 건너뜀
            continue;

        // "/proc/<tid>/stat" 파일 경로 생성
        snprintf(buf, sizeof(buf), "/proc/%d/stat", tl->tid);

        // "/proc/<tid>/stat" 파일을 읽기 모드로 엶
        fd = open(buf, O_RDONLY);
        if (fd < 0) {  // 파일 열기 실패 시 스레드가 종료된 것으로 처리
            tl->exited = true;
            continue;
        }

        // 파일 내용을 읽음
        len = read(fd, line, sizeof(line) - 1);
        if (len < 0) {  // 읽기 실패 시 스레드가 종료된 것으로 처리
            tl->exited = true;
            close(fd);  // 파일 닫기
            continue;
        }

        line[len] = '\0';  // 읽은 데이터의 끝에 NULL 문자 추가

        // 읽은 데이터에서 스레드 상태 문자를 추출 ('Z'는 좀비 상태)
        sscanf(line, "%*d %*s %c", &state);
        if (state == 'Z')  // 스레드가 좀비 상태일 경우
            tl->exited = true;

        close(fd);  // 파일 닫기
    }

    // 모든 스레드가 종료되었는지 다시 확인
    list_for_each_entry(tl, &tid_list_head, list) {
        if (!tl->exited)  // 종료되지 않은 스레드가 있으면 false 반환
            return false;
    }

    pr_dbg2("all process/thread exited\n");  // 디버그 메시지: 모든 프로세스/스레드가 종료됨
    child_exited = true;  // 자식 프로세스가 모두 종료되었음을 나타내는 플래그 설정
    return true;  // 모든 스레드가 종료되었음을 반환
}

struct dlopen_list {
    // 동적으로 로드된 라이브러리의 리스트 항목 구조체
    struct list_head list;  // 리스트 헤더 (링크드 리스트로 사용)
    char *libname;  // 라이브러리 이름을 저장할 문자열 포인터
};

static LIST_HEAD(dlopen_libs); 
// 동적으로 로드된 라이브러리들의 리스트

static void read_record_mmap(int pfd, const char *dirname, int bufsize)
{
    // 기록된 mmap 데이터를 읽고 처리하는 함수
    char buf[128];  // 버퍼
    struct shmem_list *sl, *tmp;  // 공유 메모리 리스트 포인터
    struct tid_list *tl, *pos;  // 스레드 리스트 포인터
    struct uftrace_msg msg;  // uftrace 메시지 구조체
    struct uftrace_msg_task tmsg;  // uftrace 작업 메시지 구조체
    struct uftrace_msg_sess sess;  // uftrace 세션 메시지 구조체
    struct uftrace_msg_dlopen dmsg;  // uftrace 동적 라이브러리 메시지 구조체
    struct dlopen_list *dlib;  // 동적 라이브러리 리스트 포인터
    char *exename;  // 실행 파일 이름
    int lost;  // 잃어버린 메시지 개수

    // 파이프에서 메시지 읽기
    if (read_all(pfd, &msg, sizeof(msg)) < 0)
        pr_err("reading pipe failed:");

    // 메시지 매직 넘버가 유효한지 확인
    if (msg.magic != UFTRACE_MSG_MAGIC)
        pr_err_ns("invalid message received: %x\n", msg.magic);

    // 메시지 타입에 따라 처리 분기
    switch (msg.type) {
    case UFTRACE_MSG_REC_START:
        // 녹화 시작 메시지 처리
        if (msg.len >= SHMEM_NAME_SIZE)
            pr_err_ns("invalid message length\n");

        sl = xmalloc(sizeof(*sl));  // 공유 메모리 리스트 항목 메모리 할당

        // 파이프에서 메시지 ID 읽기
        if (read_all(pfd, sl->id, msg.len) < 0)
            pr_err("reading pipe failed");

        sl->id[msg.len] = '\0';  // 메시지 끝에 NULL 문자 추가
        pr_dbg2("MSG START: %s\n", sl->id);  // 디버그 메시지 출력

        // 공유 메모리 리스트에 항목 추가
        list_add_tail(&sl->list, &shmem_list_head);
        break;

    case UFTRACE_MSG_REC_END:
        // 녹화 종료 메시지 처리
        if (msg.len >= SHMEM_NAME_SIZE)
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, buf, msg.len) < 0)
            pr_err("reading pipe failed");

        buf[msg.len] = '\0';  // 메시지 끝에 NULL 문자 추가
        pr_dbg2("MSG  END : %s\n", buf);  // 디버그 메시지 출력

        // 공유 메모리 리스트에서 항목 제거
        list_for_each_entry_safe(sl, tmp, &shmem_list_head, list) {
            if (!memcmp(sl->id, buf, msg.len)) {  // ID가 일치하는 항목 찾기
                list_del(&sl->list);  // 리스트에서 제거
                free(sl);  // 메모리 해제
                break;
            }
        }

        // mmap 파일 기록
        record_mmap_file(dirname, buf, bufsize);
        break;

    case UFTRACE_MSG_TASK_START:
        // 작업 시작 메시지 처리
        if (msg.len != sizeof(tmsg))
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
            pr_err("reading pipe failed");

        pr_dbg2("MSG TASK_START : %d/%d\n", tmsg.pid, tmsg.tid);  // 디버그 메시지 출력

        // 기존의 스레드 ID 확인 (exec로 인한 처리)
        list_for_each_entry(pos, &tid_list_head, list) {
            if (pos->tid == tmsg.tid) {
                flush_old_shmem(dirname, tmsg.tid, bufsize);  // 오래된 공유 메모리 플러시
                break;
            }
        }

        // 리스트에 항목이 없으면 새로 추가
        if (list_no_entry(pos, &tid_list_head, list))
            add_tid_list(tmsg.pid, tmsg.tid);

        // 작업 정보 기록
        write_task_info(dirname, &tmsg);
        break;

    case UFTRACE_MSG_TASK_END:
        // 작업 종료 메시지 처리
        if (msg.len != sizeof(tmsg))
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
            pr_err("reading pipe failed");

        pr_dbg2("MSG TASK_END : %d/%d\n", tmsg.pid, tmsg.tid);  // 디버그 메시지 출력

        // 스레드 종료 상태로 표시
        list_for_each_entry(pos, &tid_list_head, list) {
            if (pos->tid == tmsg.tid) {
                pos->exited = true;
                break;
            }
        }
        break;

    case UFTRACE_MSG_FORK_START:
        // 포크 시작 메시지 처리
        if (msg.len != sizeof(tmsg))
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
            pr_err("reading pipe failed");

        pr_dbg2("MSG FORK1: %d/%d\n", tmsg.pid, -1);  // 디버그 메시지 출력

        // 스레드 리스트에 항목 추가 (포크 시작)
        add_tid_list(tmsg.pid, -1);
        break;

    case UFTRACE_MSG_FORK_END:
        // 포크 종료 메시지 처리
        if (msg.len != sizeof(tmsg))
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
            pr_err("reading pipe failed");

        // 포크된 프로세스와 스레드 찾기
        list_for_each_entry(tl, &tid_list_head, list) {
            if (tl->pid == tmsg.pid && tl->tid == -1)
                break;
        }

        // 부모 프로세스를 찾지 못한 경우 처리
        if (list_no_entry(tl, &tid_list_head, list)) {
            list_for_each_entry(tl, &tid_list_head, list) {
                if (tl->tid == -1) {
                    pr_dbg3("override parent of daemon to %d\n", tl->pid);
                    tmsg.pid = tl->pid;
                    break;
                }
            }
        }

        // 여전히 찾지 못하면 에러 메시지 출력
        if (list_no_entry(tl, &tid_list_head, list))
            pr_err("cannot find fork pid: %d\n", tmsg.pid);

        // 스레드 ID 설정
        tl->tid = tmsg.tid;

        pr_dbg2("MSG FORK2: %d/%d\n", tl->pid, tl->tid);  // 디버그 메시지 출력

        // 포크 정보 기록
        write_fork_info(dirname, &tmsg);
        break;

    case UFTRACE_MSG_SESSION:
        // 세션 메시지 처리
        if (msg.len < sizeof(sess))
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, &sess, sizeof(sess)) < 0)
            pr_err("reading pipe failed");

        // 실행 파일 이름 읽기
        exename = xmalloc(sess.namelen + 1);
        if (read_all(pfd, exename, sess.namelen) < 0)
            pr_err("reading pipe failed");
        exename[sess.namelen] = '\0';  // 실행 파일 이름 끝에 NULL 문자 추가

        // 세션 ID를 buf에 복사
        memcpy(buf, sess.sid, 16);
        buf[16] = '\0';

        pr_dbg2("MSG SESSION: %d: %s (%s)\n", sess.task.tid, exename, buf);  // 디버그 메시지 출력

        // 세션 정보 기록
        write_session_info(dirname, &sess, exename);
        free(exename);  // 메모리 해제
        break;

    case UFTRACE_MSG_LOST:
        // 메시지 손실 처리
        if (msg.len < sizeof(lost))
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, &lost, sizeof(lost)) < 0)
            pr_err("reading pipe failed");

        shmem_lost_count += lost;  // 손실된 메시지 수 증가
        break;

    case UFTRACE_MSG_DLOPEN:
        // 동적 라이브러리 로드 메시지 처리
        if (msg.len < sizeof(dmsg))
            pr_err_ns("invalid message length\n");

        if (read_all(pfd, &dmsg, sizeof(dmsg)) < 0)
            pr_err("reading pipe failed");

        // 라이브러리 이름 읽기
        exename = xmalloc(dmsg.namelen + 1);
        if (read_all(pfd, exename, dmsg.namelen) < 0)
            pr_err("reading pipe failed");
        exename[dmsg.namelen] = '\0';

        pr_dbg2("MSG DLOPEN: %d: %#lx %s\n", dmsg.task.tid, dmsg.base_addr, exename);  // 디버그 메시지 출력

        // 동적 라이브러리 리스트에 항목 추가
        dlib = xmalloc(sizeof(*dlib));
        dlib->libname = exename;
        list_add_tail(&dlib->list, &dlopen_libs);

        // 동적 라이브러리 로드 정보 기록
        write_dlopen_info(dirname, &dmsg, exename);
        // exename은 dlib과 함께 해제됨
        break;

    case UFTRACE_MSG_FINISH:
        // 처리 완료 메시지
        pr_dbg2("MSG FINISH\n");
        finish_received = true;  // 완료 플래그 설정
        break;

    default:
        // 알 수 없는 메시지 타입 처리
        pr_warn("Unknown message type: %u\n", msg.type);  // 경고 메시지 출력
        break;
    }
}
static void send_task_file(int sock, const char *dirname)
{
    // "task.txt" 파일을 네트워크 소켓을 통해 전송하는 함수
    send_trace_metadata(sock, dirname, "task.txt");  // 소켓을 통해 "task.txt" 메타데이터 전송
}

/* find "sid-XXX.map" file */
static int filter_map(const struct dirent *de)
{
    // "sid-XXX.map" 파일을 찾기 위한 필터 함수
    size_t len = strlen(de->d_name);  // 파일 이름의 길이를 계산

    // 파일 이름이 "sid-"로 시작하고 ".map"으로 끝나는지 확인
    return !strncmp("sid-", de->d_name, 4) && !strncmp(".map", de->d_name + len - 4, 4);
}

static void send_map_files(int sock, const char *dirname)
{
    // 네트워크 소켓을 통해 ".map" 파일들을 전송하는 함수
    int i, maps;  // 반복 변수와 스캔된 파일 개수
    struct dirent **map_list;  // 스캔된 디렉토리 항목 리스트

    // 디렉토리에서 "sid-XXX.map" 파일 목록을 스캔
    maps = scandir(dirname, &map_list, filter_map, alphasort);
    if (maps < 0)
        pr_err("cannot scan map files");  // 파일 스캔 실패 시 오류 출력

    // 스캔된 모든 ".map" 파일들을 소켓으로 전송
    for (i = 0; i < maps; i++) {
        send_trace_metadata(sock, dirname, map_list[i]->d_name);  // 메타데이터 전송
        free(map_list[i]);  // 디렉토리 항목 메모리 해제
    }
    free(map_list);  // 리스트 메모리 해제
}

/* find "XXX.sym" file */
static int filter_sym(const struct dirent *de)
{
    // ".sym" 파일을 찾기 위한 필터 함수
    size_t len = strlen(de->d_name);  // 파일 이름의 길이를 계산

    // 파일 이름이 ".sym"으로 끝나는지 확인
    return !strncmp(".sym", de->d_name + len - 4, 4);
}

static void send_sym_files(int sock, const char *dirname)
{
    // 네트워크 소켓을 통해 ".sym" 파일들을 전송하는 함수
    int i, syms;  // 반복 변수와 스캔된 파일 개수
    struct dirent **sym_list;  // 스캔된 디렉토리 항목 리스트

    // 디렉토리에서 ".sym" 파일 목록을 스캔
    syms = scandir(dirname, &sym_list, filter_sym, alphasort);
    if (syms < 0)
        pr_err("cannot scan sym files");  // 파일 스캔 실패 시 오류 출력

    // 스캔된 모든 ".sym" 파일들을 소켓으로 전송
    for (i = 0; i < syms; i++) {
        send_trace_metadata(sock, dirname, sym_list[i]->d_name);  // 메타데이터 전송
        free(sym_list[i]);  // 디렉토리 항목 메모리 해제
    }
    free(sym_list);  // 리스트 메모리 해제
}
/* find "XXX.dbg" file */
static int filter_dbg(const struct dirent *de)
{
    // ".dbg" 확장자를 가진 파일을 찾기 위한 필터 함수
    size_t len = strlen(de->d_name);  // 파일 이름의 길이 계산

    // 파일 이름이 ".dbg"로 끝나는지 확인
    return !strncmp(".dbg", de->d_name + len - 4, 4);
}

static void send_dbg_files(int sock, const char *dirname)
{
    // 네트워크 소켓을 통해 ".dbg" 파일들을 전송하는 함수
    int i, dbgs;  // 반복 변수와 스캔된 파일 개수
    struct dirent **dbg_list;  // 스캔된 디렉토리 항목 리스트

    // 디렉토리에서 ".dbg" 파일 목록을 스캔
    dbgs = scandir(dirname, &dbg_list, filter_dbg, alphasort);
    if (dbgs < 0)
        pr_err("cannot scan dbg files");  // 파일 스캔 실패 시 오류 출력

    // 스캔된 모든 ".dbg" 파일들을 소켓으로 전송
    for (i = 0; i < dbgs; i++) {
        send_trace_metadata(sock, dirname, dbg_list[i]->d_name);  // 메타데이터 전송
        free(dbg_list[i]);  // 디렉토리 항목 메모리 해제
    }
    free(dbg_list);  // 리스트 메모리 해제
}

static void send_info_file(int sock, const char *dirname)
{
    // "info" 파일을 네트워크 소켓을 통해 전송하는 함수
    int fd;  // 파일 디스크립터
    char *filename = NULL;  // 파일 이름 포인터
    struct uftrace_file_header hdr;  // uftrace 파일 헤더 구조체
    struct stat stbuf;  // 파일 상태 구조체
    void *info;  // 파일 내용을 저장할 버퍼
    int len;  // 파일 크기

    // "info" 파일 경로 생성
    xasprintf(&filename, "%s/info", dirname);
    fd = open(filename, O_RDONLY);  // 파일을 읽기 모드로 열기
    if (fd < 0)
        pr_err("open info failed");  // 파일 열기 실패 시 오류 출력

    // 파일 상태 정보 가져오기
    if (fstat(fd, &stbuf) < 0)
        pr_err("stat info failed");  // 파일 상태 정보 가져오기 실패 시 오류 출력

    // 파일에서 헤더 정보 읽기
    if (read_all(fd, &hdr, sizeof(hdr)) < 0)
        pr_err("read file header failed");  // 헤더 읽기 실패 시 오류 출력

    // 헤더 크기를 제외한 파일 내용을 읽기 위한 크기 계산
    len = stbuf.st_size - sizeof(hdr);
    info = xmalloc(len);  // 파일 내용을 저장할 버퍼 할당

    // 파일에서 내용을 읽기
    if (read_all(fd, info, len) < 0)
        pr_err("read info failed");  // 내용 읽기 실패 시 오류 출력

    // 소켓으로 파일 정보 전송
    send_trace_info(sock, &hdr, info, len);

    close(fd);  // 파일 닫기
    free(info);  // 버퍼 메모리 해제
    free(filename);  // 파일명 메모리 해제
}

static void send_kernel_metadata(int sock, const char *dirname)
{
    // 커널 메타데이터 파일을 네트워크 소켓을 통해 전송하는 함수
    send_trace_metadata(sock, dirname, "kernel_header");  // "kernel_header" 파일 전송
    send_trace_metadata(sock, dirname, "kallsyms");  // "kallsyms" 파일 전송
}

static void send_event_file(int sock, const char *dirname)
{
    // "events.txt" 파일을 네트워크 소켓을 통해 전송하는 함수
    char buf[PATH_MAX];  // 파일 경로 버퍼

    // "events.txt" 파일 경로 생성
    snprintf(buf, sizeof(buf), "%s/events.txt", dirname);
    if (access(buf, F_OK) != 0)
        return;  // 파일이 존재하지 않으면 함수 종료

    // "events.txt" 파일 전송
    send_trace_metadata(sock, dirname, "events.txt");
}

static void send_log_file(int sock, const char *dirname, const char *logfile)
{
    // 로그 파일을 네트워크 소켓을 통해 전송하는 함수
    if (access(logfile, F_OK) != 0)
        return;  // 로그 파일이 존재하지 않으면 함수 종료

    // 로그 파일 전송
    send_trace_metadata(sock, dirname, (char *)logfile);
}
static void update_session_maps(struct uftrace_opts *opts)
{
    // 세션의 맵 파일을 업데이트하는 함수
    struct dirent **map_list;  // 디렉토리 항목 리스트
    int i, maps;  // 반복 변수와 맵 파일 개수

    // 디렉토리에서 "sid-XXX.map" 파일 목록을 스캔
    maps = scandir(opts->dirname, &map_list, filter_map, alphasort);
    if (maps <= 0) {
        // 맵 파일이 없거나 스캔 실패 시 오류 출력
        if (maps == 0)
            errno = ENOENT;  // "파일 없음" 오류 코드 설정
        pr_err("cannot find map files");  // 오류 메시지 출력
    }

    // 스캔된 모든 맵 파일에 대해 세션 맵 업데이트 수행
    for (i = 0; i < maps; i++) {
        char buf[PATH_MAX];  // 경로 버퍼

        // 맵 파일 경로 생성
        snprintf(buf, sizeof(buf), "%s/%s", opts->dirname, map_list[i]->d_name);
        update_session_map(buf);  // 세션 맵 업데이트
        free(map_list[i]);  // 디렉토리 항목 메모리 해제
    }

    free(map_list);  // 맵 리스트 메모리 해제
}

static void load_session_symbols(struct uftrace_opts *opts)
{
    // 세션의 심볼(symbol) 정보를 로드하는 함수
    struct dirent **map_list;  // 디렉토리 항목 리스트
    int i, maps;  // 반복 변수와 맵 파일 개수

    // 디렉토리에서 "sid-XXX.map" 파일 목록을 스캔
    maps = scandir(opts->dirname, &map_list, filter_map, alphasort);
    if (maps <= 0) {
        // 맵 파일이 없거나 스캔 실패 시 오류 출력
        if (maps == 0)
            errno = ENOENT;  // "파일 없음" 오류 코드 설정
        pr_err("cannot find map files");  // 오류 메시지 출력
    }

    // 스캔된 모든 맵 파일에 대해 세션 심볼 로드 수행
    for (i = 0; i < maps; i++) {
        struct uftrace_sym_info sinfo = {
            .dirname = opts->dirname,
            .flags = SYMTAB_FL_ADJ_OFFSET,  // 심볼 테이블의 오프셋 조정 플래그 설정
        };
        char sid[20];  // 세션 ID 저장용 버퍼

        // 맵 파일 이름에서 세션 ID 추출
        sscanf(map_list[i]->d_name, "sid-%[^.].map", sid);
        free(map_list[i]);  // 디렉토리 항목 메모리 해제

        pr_dbg2("reading symbols for session %s\n", sid);  // 디버그 메시지 출력
        read_session_map(opts->dirname, &sinfo, sid);  // 세션 맵 읽기

        load_module_symtabs(&sinfo);  // 모듈 심볼 테이블 로드

        delete_session_map(&sinfo);  // 세션 맵 삭제
    }

    free(map_list);  // 맵 리스트 메모리 해제
}

static char *get_child_time(struct timespec *ts1, struct timespec *ts2)
{
    // 두 시간(ts1, ts2) 사이의 경과 시간을 계산하여 문자열로 반환하는 함수
#define SEC_TO_NSEC (1000000000ULL)  // 초를 나노초로 변환하는 상수

    char *elapsed_time = NULL;  // 경과 시간을 저장할 문자열 포인터
    uint64_t sec = ts2->tv_sec - ts1->tv_sec;  // 초 단위 경과 시간 계산
    uint64_t nsec = ts2->tv_nsec - ts1->tv_nsec;  // 나노초 단위 경과 시간 계산

    // 나노초 경과 시간이 1초(SEC_TO_NSEC)보다 크면 초에서 1초를 빼고 나노초를 조정
    if (nsec > SEC_TO_NSEC) {
        nsec += SEC_TO_NSEC;
        sec--;
    }

    // 경과 시간을 문자열로 변환
    xasprintf(&elapsed_time, "%" PRIu64 ".%09" PRIu64 " sec", sec, nsec);
    return elapsed_time;  // 경과 시간 문자열 반환
}

static void print_child_time(char *elapsed_time)
{
    // 경과 시간을 출력하는 함수
    pr_out("elapsed time: %20s\n", elapsed_time);  // 경과 시간 출력
}

static void print_child_usage(struct rusage *ru)
{
    // 자식 프로세스의 시스템 및 사용자 시간을 출력하는 함수
    pr_out(" system time: %6lu.%06lu000 sec\n", ru->ru_stime.tv_sec, ru->ru_stime.tv_usec);  // 시스템 시간 출력
    pr_out("   user time: %6lu.%06lu000 sec\n", ru->ru_utime.tv_sec, ru->ru_utime.tv_usec);  // 사용자 시간 출력
}

#define UFTRACE_MSG "Cannot trace '%s': No such executable file.\n"
// 오류 메시지 상수: 실행 파일을 찾을 수 없을 때 출력할 메시지
#define MCOUNT_MSG                                                                                 \
    "Can't find '%s' symbol in the '%s'.\n"                                                    \
    "\tIt seems not to be compiled with -pg or -finstrument-functions flag.\n"                 \
    "\tYou can rebuild your program with it or use -P option for dynamic tracing.\n"
// 프로그램이 -pg 또는 -finstrument-functions 플래그로 컴파일되지 않았을 때 출력할 메시지 정의

#define UFTRACE_ELF_MSG                                                                            \
    "Cannot trace '%s': Invalid file\n"                                                        \
    "\tThis file doesn't look like an executable ELF file.\n"                                  \
    "\tPlease check whether it's a kind of script or shell functions.\n"
// ELF 파일 형식이 아닌 경우 출력할 오류 메시지 정의

#define MACHINE_MSG                                                                                \
    "Cannot trace '%s': Unsupported machine\n"                                                 \
    "\tThis machine type (%u) is not supported currently.\n"                                   \
    "\tSorry about that!\n"
// 지원하지 않는 기계 유형에서 추적을 시도할 때 출력할 메시지 정의

#define ARGUMENT_MSG "uftrace: -A or -R might not work for binaries with -finstrument-functions\n"
// -A 또는 -R 옵션이 -finstrument-functions로 컴파일된 바이너리에서 작동하지 않을 수 있음을 알리는 메시지 정의

#define STATIC_MSG                                                                                 \
    "Cannot trace static binary: %s\n"                                                         \
    "\tIt seems to be compiled with -static, rebuild the binary without it.\n"
// 정적 바이너리(static binary)에서 추적할 수 없을 때 출력할 메시지 정의

#define SCRIPT_MSG                                                                                 \
    "Cannot trace script file: %s\n"                                                           \
    "\tTo trace binaries run by the script, use --force option.\n"
// 스크립트 파일에서 추적을 시도할 때 --force 옵션을 사용하라는 메시지 정의

#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif
// AARCH64(ARM 64-bit) 아키텍처에 대한 ELF 머신 값 정의

static bool is_regular_executable(const char *pathname)
{
    // 주어진 경로의 파일이 정규 실행 파일인지 확인하는 함수
    struct stat sb;

    // 파일 경로에 대한 정보를 가져옴
    if (!stat(pathname, &sb)) {
        // 파일이 정규 파일이고 실행 권한이 있으면 true 반환
        if (S_ISREG(sb.st_mode) && (sb.st_mode & S_IXUSR))
            return true;
    }
    return false;  // 그렇지 않으면 false 반환
}

static void find_in_path(char *exename, char *buf, size_t len)
{
    // PATH 환경 변수에서 주어진 실행 파일을 찾는 함수
    struct strv strv = STRV_INIT;  // 문자열 벡터 초기화
    char *env = getenv("PATH");  // PATH 환경 변수 값 가져오기
    char *path;  // 개별 경로를 저장할 포인터
    bool found = false;  // 파일이 발견되었는지 여부를 추적하는 플래그
    int i;  // 반복 변수

    // 환경 변수가 없거나 절대 경로로 주어진 경우 오류 메시지 출력
    if (!env || exename[0] == '/')
        pr_err_ns(UFTRACE_MSG, exename);

    // PATH 환경 변수를 ":"로 분리하여 경로 목록 생성
    strv_split(&strv, env, ":");

    // PATH에 있는 각 경로에 대해 실행 파일을 찾음
    strv_for_each(&strv, path, i) {
        // 각 경로와 실행 파일 이름을 결합하여 전체 경로를 생성
        snprintf(buf, len, "%s/%s", path, exename);
        if (is_regular_executable(buf)) {
            found = true;  // 실행 파일을 찾으면 found 플래그를 true로 설정
            break;  // 더 이상 탐색하지 않고 루프 종료
        }
    }

    // 실행 파일을 찾지 못한 경우 오류 메시지 출력
    if (!found)
        pr_err_ns(UFTRACE_MSG, exename);

    // 문자열 벡터 메모리 해제
    strv_free(&strv);
}
static void check_binary(struct uftrace_opts *opts)
{
    // 실행 파일이 유효한지 확인하고, 실행 가능 상태인지 검사하는 함수
    int fd;  // 파일 디스크립터
    int chk;  // 정적 바이너리인지 확인하는 변수
    size_t i;  // 반복 변수
    char elf_ident[EI_NIDENT];  // ELF 파일 헤더 식별자를 저장할 버퍼
    static char altname[PATH_MAX];  // opts->exename을 유지하기 위한 대체 이름 버퍼
    uint16_t e_type;  // ELF 파일 타입 (실행 파일, 공유 라이브러리 등)
    uint16_t e_machine;  // ELF 파일의 아키텍처 정보
    uint16_t supported_machines[] = { EM_X86_64, EM_ARM, EM_AARCH64, EM_386, EM_RISCV };  // 지원하는 기계 유형

again:
    /* 경로에서 실행 파일을 찾을 수 없으면 PATH 환경 변수에서 찾음 */
    if (!is_regular_executable(opts->exename)) {
        find_in_path(opts->exename, altname, sizeof(altname));  // PATH에서 실행 파일 찾기
        opts->exename = altname;  // 실행 파일 경로를 대체 이름으로 설정
    }

    pr_dbg("checking binary %s\n", opts->exename);  // 디버그 메시지 출력

    // 실행 파일을 읽기 전용으로 엶
    fd = open(opts->exename, O_RDONLY);
    if (fd < 0)
        pr_err("Cannot open '%s'", opts->exename);  // 파일 열기 실패 시 오류 출력

    // ELF 파일 헤더 식별자 읽기
    if (read(fd, elf_ident, sizeof(elf_ident)) < 0)
        pr_err("Cannot read '%s'", opts->exename);  // 읽기 실패 시 오류 출력

    // ELF 매직 넘버(ELFMAG)와 일치하는지 확인
    if (memcmp(elf_ident, ELFMAG, SELFMAG)) {
        char *script = altname;  // 스크립트 파일 경로 저장
        char *p;

        // 스크립트 파일인지 확인
        if (!check_script_file(opts->exename, altname, sizeof(altname)))
            pr_err_ns(UFTRACE_ELF_MSG, opts->exename);  // 스크립트가 아니면 오류 메시지 출력

#if defined(HAVE_LIBPYTHON2) || defined(HAVE_LIBPYTHON3)
        // 파이썬 스크립트 파일인 경우 옵션 설정
        if (strstr(script, "python")) {
            opts->force = true;  // 강제 추적 옵션 설정
            opts->no_sched = true;  // 스케줄 이벤트 비활성화
        }
#endif

        // 강제 옵션이나 패치 옵션이 없으면 스크립트 메시지 출력
        if (!opts->force && !opts->patch)
            pr_err_ns(SCRIPT_MSG, opts->exename);

        // 스크립트에서 옵션 제거
        script = str_ltrim(script);
        p = strchr(script, ' ');
        if (p)
            *p = '\0';

        // 스크립트 이름을 실행 파일 이름으로 설정
        opts->exename = script;
        close(fd);  // 파일 디스크립터 닫기
        goto again;  // 다시 실행 파일 확인 루틴으로 돌아감
    }

    // ELF 파일의 타입(e_type) 읽기 (실행 파일인지 공유 라이브러리인지 등)
    if (read(fd, &e_type, sizeof(e_type)) < 0)
        pr_err("Cannot read '%s'", opts->exename);  // 읽기 실패 시 오류 출력

    // 실행 파일(ET_EXEC) 또는 동적 라이브러리(ET_DYN)인지 확인
    if (e_type != ET_EXEC && e_type != ET_DYN)
        pr_err_ns(UFTRACE_ELF_MSG, opts->exename);  // 그렇지 않으면 오류 메시지 출력

    // ELF 파일의 아키텍처 정보(e_machine) 읽기
    if (read(fd, &e_machine, sizeof(e_machine)) < 0)
        pr_err("Cannot read '%s'", opts->exename);  // 읽기 실패 시 오류 출력

    // 지원하는 아키텍처인지 확인
    for (i = 0; i < ARRAY_SIZE(supported_machines); i++) {
        if (e_machine == supported_machines[i])
            break;  // 지원하는 아키텍처일 경우 루프 종료
    }
    if (i == ARRAY_SIZE(supported_machines))
        pr_err_ns(MACHINE_MSG, opts->exename, e_machine);  // 지원하지 않으면 오류 메시지 출력

    // 정적 바이너리인지 확인
    chk = check_static_binary(opts->exename);
    if (chk) {
        if (chk < 0)
            pr_err_ns("Cannot check '%s'\n", opts->exename);  // 검사 실패 시 오류 메시지 출력
        else
            pr_err_ns(STATIC_MSG, opts->exename);  // 정적 바이너리일 경우 오류 메시지 출력
    }

    // 강제 추적 옵션이 없는 경우 추가 검사
    if (!opts->force) {
        enum uftrace_trace_type chk_type;

        chk_type = check_trace_functions(opts->exename);  // 추적할 함수가 있는지 확인

        // 추적할 함수가 없고 패치 옵션도 없으면 오류 메시지 출력
        if (chk_type == TRACE_NONE && !opts->patch) {
            pr_err_ns(MCOUNT_MSG, "mcount", opts->exename);
        }
        // -finstrument-functions로 컴파일된 바이너리에서 인자/반환값 추적 옵션이 비활성화된 경우
        else if (chk_type == TRACE_CYGPROF && (opts->args || opts->retval)) {
            pr_out(ARGUMENT_MSG);  // 경고 메시지 출력
        }
        // 오류가 발생한 경우 오류 메시지 출력
        else if (chk_type == TRACE_ERROR) {
            pr_err_ns("Cannot check '%s'\n", opts->exename);
        }
    }

    close(fd);  // 파일 디스크립터 닫기
}
static void check_perf_event(struct uftrace_opts *opts)
{
    // 성능 이벤트(performance event)를 확인하고, 스케줄링 이벤트(scheduling event) 설정 여부를 결정하는 함수
    struct strv strv = STRV_INIT;  // 문자열 벡터(strv) 초기화
    char *evt;  // 개별 이벤트를 저장할 포인터
    int i;  // 반복 변수
    bool found = false;  // 이벤트가 발견되었는지 여부를 추적하는 플래그
    enum uftrace_pattern_type ptype = opts->patt_type;  // 패턴 타입 설정

    // 기본적으로 성능 이벤트 및 스케줄링 이벤트 설정 여부를 지정
    has_perf_event = has_sched_event = !opts->no_event;  // 이벤트를 비활성화하지 않은 경우 true로 설정

    if (opts->no_sched)  // 스케줄링 이벤트 비활성화 옵션이 설정된 경우
        has_sched_event = false;  // 스케줄링 이벤트를 비활성화

    if (opts->event == NULL)  // 이벤트가 지정되지 않은 경우 함수 종료
        return;

    // opts->event를 ";"로 분리하여 문자열 벡터로 저장
    strv_split(&strv, opts->event, ";");

    // 문자열 벡터에서 각 이벤트를 순회하며 처리
    strv_for_each(&strv, evt, i) {
        struct uftrace_pattern patt;  // 필터 패턴 구조체

        init_filter_pattern(ptype, &patt, evt);  // 이벤트에 대해 필터 패턴 초기화

        // "linux:task-new", "linux:task-exit", "linux:task-name" 이벤트와 일치하는지 확인
        if (match_filter_pattern(&patt, "linux:task-new") ||
            match_filter_pattern(&patt, "linux:task-exit") ||
            match_filter_pattern(&patt, "linux:task-name"))
            found = true;  // 일치하는 이벤트가 발견되면 found 플래그를 true로 설정

        // 스케줄링 관련 이벤트와 일치하는지 확인
        if (match_filter_pattern(&patt, "linux:sched-in") ||
            match_filter_pattern(&patt, "linux:sched-out") ||
            match_filter_pattern(&patt, "linux:schedule")) {
            has_sched_event = true;  // 스케줄링 이벤트가 발견되면 스케줄링 이벤트 활성화
            found = true;  // 일치하는 이벤트가 발견되었으므로 found 플래그 설정
        }

        free_filter_pattern(&patt);  // 필터 패턴 해제

        // 이벤트가 발견되고 스케줄링 이벤트가 활성화된 경우 루프 종료
        if (found && has_sched_event)
            break;
    }

    // 문자열 벡터 메모리 해제
    strv_free(&strv);

    // 성능 이벤트가 발견된 경우 has_perf_event를 true로 설정
    has_perf_event = found;
}
struct writer_data {
    // 기록 스레드에 대한 데이터를 저장하는 구조체
    int pid;  // 프로세스 ID
    int pipefd;  // 파이프 파일 디스크립터
    int sock;  // 소켓 파일 디스크립터
    int nr_cpu;  // 사용 가능한 CPU 수
    int status;  // 상태 코드
    pthread_t *writers;  // 스레드 배열
    struct timespec ts1, ts2;  // 시간 측정용 타임스펙 구조체
    struct rusage usage;  // 리소스 사용 정보 구조체
    struct uftrace_kernel_writer kernel;  // 커널 기록 구조체
    struct uftrace_perf_writer perf;  // 성능 기록 구조체
};

static void setup_writers(struct writer_data *wd, struct uftrace_opts *opts)
{
    // 기록 스레드를 설정하는 함수
    struct uftrace_kernel_writer *kernel = &wd->kernel;  // 커널 기록에 대한 포인터
    struct uftrace_perf_writer *perf = &wd->perf;  // 성능 기록에 대한 포인터
    struct sigaction sa = {
        .sa_flags = 0,  // 시그널 행동 플래그 설정
    };

    // 옵션에 nop이 설정된 경우
    if (opts->nop) {
        opts->nr_thread = 0;  // 스레드 수를 0으로 설정
        opts->kernel = false;  // 커널 추적 비활성화
        has_perf_event = false;  // 성능 이벤트 비활성화
        wd->nr_cpu = 0;  // CPU 수를 0으로 설정

        goto out;  // 나머지 설정을 건너뛰고 함수 종료
    }

    // SIGCHLD 시그널 설정
    sigfillset(&sa.sa_mask);  // 시그널 마스크를 모든 시그널로 설정
    sa.sa_handler = NULL;  // 핸들러는 사용하지 않음
    sa.sa_sigaction = sigchld_handler;  // SIGCHLD 처리 함수 설정
    sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;  // 시그널 플래그 설정
    sigaction(SIGCHLD, &sa, NULL);  // SIGCHLD 시그널 처리 설정

    // 호스트 옵션이 설정된 경우
    if (opts->host) {
        wd->sock = setup_client_socket(opts);  // 클라이언트 소켓 설정
        send_trace_dir_name(wd->sock, opts->dirname);  // 소켓으로 디렉토리 이름 전송
    }
    else
        wd->sock = -1;  // 소켓이 없음을 나타내기 위해 -1로 설정

    // 사용 가능한 CPU 수를 가져옴
    wd->nr_cpu = sysconf(_SC_NPROCESSORS_ONLN);  // 현재 온라인인 CPU 수를 가져옴
    if (unlikely(wd->nr_cpu <= 0)) {  // CPU 수를 가져오지 못한 경우
        wd->nr_cpu = sysconf(_SC_NPROCESSORS_CONF);  // CPU 설정 수를 가져옴
        if (wd->nr_cpu <= 0)
            pr_err("cannot know number of cpu");  // 오류 메시지 출력
    }

    // 커널 이벤트 또는 커널 추적이 활성화된 경우
    if (opts->kernel || has_kernel_event(opts->event)) {
        int err;

        // 커널 기록 설정
        kernel->pid = wd->pid;  // 프로세스 ID 설정
        kernel->output_dir = opts->dirname;  // 출력 디렉토리 설정
        kernel->depth = opts->kernel_depth;  // 커널 깊이 설정
        kernel->bufsize = opts->kernel_bufsize;  // 버퍼 크기 설정
        kernel->clock = opts->clock;  // 클록 설정

        // 스레드 수가 설정되지 않은 경우 커널 깊이에 따라 스레드 수 결정
        if (!opts->nr_thread) {
            if (opts->kernel_depth >= 4)
                opts->nr_thread = wd->nr_cpu;  // CPU 수만큼 스레드 생성
            else if (opts->kernel_depth >= 2)
                opts->nr_thread = wd->nr_cpu / 2;  // CPU의 절반만큼 스레드 생성
        }

        // 커널 버퍼 크기가 설정되지 않은 경우 깊이에 따라 버퍼 크기 설정
        if (!opts->kernel_bufsize) {
            if (opts->kernel_depth >= 8)
                kernel->bufsize = PATH_MAX * 1024;  // 깊이가 8 이상이면 큰 버퍼 사용
            else if (opts->kernel_depth >= 4)
                kernel->bufsize = 3072 * 1024;  // 깊이가 4 이상이면 중간 버퍼 사용
            else if (opts->kernel_depth >= 2)
                kernel->bufsize = 2048 * 1024;  // 깊이가 2 이상이면 작은 버퍼 사용
        }

        // 커널 추적 설정
        err = setup_kernel_tracing(kernel, opts);
        if (err) {
            if (err == -EPERM)
                pr_warn("kernel tracing requires root privilege\n");  // 권한 부족 경고
            else
                pr_warn("kernel tracing disabled due to an error\n"
                        "is CONFIG_FUNCTION_GRAPH_TRACER enabled in the kernel?\n");  // 커널 설정 경고

            opts->kernel = false;  // 커널 추적 비활성화
        }
    }

    // 스레드 수가 설정되지 않은 경우 기본적으로 CPU 수에 따라 설정
    if (!opts->nr_thread)
        opts->nr_thread = DIV_ROUND_UP(wd->nr_cpu, 4);  // CPU 수를 4로 나누어 설정
    else if (opts->nr_thread > wd->nr_cpu)
        opts->nr_thread = wd->nr_cpu;  // 스레드 수가 CPU 수를 초과하지 않도록 제한

    // 성능 이벤트가 활성화된 경우 성능 기록 설정
    if (has_perf_event) {
        setup_clock_id(opts->clock);  // 클록 ID 설정
        if (setup_perf_record(perf, wd->nr_cpu, wd->pid, opts->dirname, has_sched_event) < 0)
            has_perf_event = false;  // 성능 기록 설정 실패 시 성능 이벤트 비활성화
    }

out:
    pr_dbg("creating %d thread(s) for recording\n", opts->nr_thread);  // 디버그 메시지 출력
    wd->writers = xmalloc(opts->nr_thread * sizeof(*wd->writers));  // 스레드 메모리 할당

    // 쓰기 스레드를 위한 파이프 생성
    if (pipe(thread_ctl) < 0)
        pr_err("cannot create a pipe for writer thread");  // 파이프 생성 실패 시 오류 출력
}

static void start_tracing(struct writer_data *wd, struct uftrace_opts *opts, int ready_fd)
{
    // 기록을 시작하는 함수. 여러 스레드를 생성하고, 커널 추적을 시작한 뒤, 준비가 완료되면 자식 프로세스에 신호를 보냄.
    int i, k;  // 반복 변수
    uint64_t go = 1;  // 자식 프로세스에 보낼 신호 값

    // 기록 시작 시간을 가져옴 (MONOTONIC 클록 사용)
    clock_gettime(CLOCK_MONOTONIC, &wd->ts1);

    // 커널 추적이 활성화되어 있으면 커널 추적을 시작
    if (opts->kernel && start_kernel_tracing(&wd->kernel) < 0) {
        opts->kernel = false;  // 오류 발생 시 커널 추적 비활성화
        pr_warn("kernel tracing disabled due to an error\n");
    }

    // 각 스레드에 대한 설정 및 생성
    for (i = 0; i < opts->nr_thread; i++) {
        struct writer_arg *warg;  // 스레드에 전달할 인수 구조체
        int cpu_per_thread = DIV_ROUND_UP(wd->nr_cpu, opts->nr_thread);  // 각 스레드에 할당할 CPU 수 계산
        size_t sizeof_warg = sizeof(*warg) + sizeof(int) * cpu_per_thread;  // warg 구조체 크기 계산

        // warg 구조체 메모리 할당 및 초기화
        warg = xzalloc(sizeof_warg);
        warg->opts = opts;
        warg->idx = i;  // 스레드 인덱스 설정
        warg->sock = wd->sock;  // 소켓 설정
        warg->kern = &wd->kernel;  // 커널 추적 설정
        warg->perf = &wd->perf;  // 성능 추적 설정
        warg->nr_cpu = 0;  // 초기 CPU 수 설정
        INIT_LIST_HEAD(&warg->list);  // 리스트 초기화
        INIT_LIST_HEAD(&warg->bufs);  // 버퍼 리스트 초기화

        // 커널 추적 또는 성능 이벤트가 활성화된 경우 CPU 할당
        if (opts->kernel || has_perf_event) {
            warg->nr_cpu = cpu_per_thread;  // 스레드 당 할당할 CPU 수 설정

            // CPU 할당
            for (k = 0; k < cpu_per_thread; k++) {
                if (i * cpu_per_thread + k < wd->nr_cpu)
                    warg->cpus[k] = i * cpu_per_thread + k;  // 할당된 CPU 설정
                else
                    warg->cpus[k] = -1;  // 할당할 CPU가 없으면 -1로 설정
            }
        }

        // writer_thread 함수를 실행할 스레드 생성
        pthread_create(&wd->writers[i], NULL, writer_thread, warg);
    }

    // 자식 프로세스에 준비가 완료되었음을 신호로 알림
    if (write(ready_fd, &go, sizeof(go)) != (ssize_t)sizeof(go))
        pr_err("signal to child failed");  // 신호 전송 실패 시 오류 출력
}

static int stop_tracing(struct writer_data *wd, struct uftrace_opts *opts)
{
    // 기록을 중지하고 결과를 처리하는 함수. 자식 프로세스의 상태를 확인하고 나머지 기록 데이터를 처리.
    int status = -1;  // 자식 프로세스의 종료 상태
    int ret = UFTRACE_EXIT_SUCCESS;  // 반환할 결과 값 (성공)

    // 자식 프로세스가 끝날 때까지 파이프에서 남은 데이터를 읽음
    while (!uftrace_done) {
        int remaining = 0;  // 파이프에 남아 있는 데이터 크기

        // 파이프에 남아 있는 데이터 크기 확인
        if (ioctl(wd->pipefd, FIONREAD, &remaining) < 0)
            break;

        if (remaining) {
            // 남은 데이터가 있으면 mmap 파일로 기록
            read_record_mmap(wd->pipefd, opts->dirname, opts->bufsize);
            continue;
        }

        // SIGCHLD 또는 FORK_END 신호를 기다림
        usleep(1000);

        // FORK_START 메시지를 받은 경우, FORK_END 메시지를 기다려야 함
        if (check_tid_list())
            break;

        if (finish_received) {
            // 추적이 완료되었음을 나타내는 메시지를 받은 경우
            status = UFTRACE_EXIT_FINISHED;
            break;
        }

        pr_dbg2("waiting for FORK2\n");  // FORK_END 메시지를 기다림
    }

    // 자식 프로세스가 종료된 경우
    if (child_exited) {
        wait4(wd->pid, &status, 0, &wd->usage);  // 자식 프로세스의 종료 상태 및 리소스 사용량 가져오기
        if (WIFEXITED(status)) {
            // 자식 프로세스가 정상 종료된 경우
            pr_dbg("child terminated with exit code: %d\n", WEXITSTATUS(status));

            if (WEXITSTATUS(status))
                ret = UFTRACE_EXIT_FAILURE;  // 종료 코드가 0이 아니면 실패로 처리
            else
                ret = UFTRACE_EXIT_SUCCESS;  // 성공적으로 종료된 경우
        }
        else if (WIFSIGNALED(status)) {
            // 자식 프로세스가 시그널로 종료된 경우
            pr_warn("child terminated by signal: %d: %s\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
            ret = UFTRACE_EXIT_SIGNALED;  // 시그널로 종료 처리
        }
        else {
            // 자식 프로세스가 알 수 없는 이유로 종료된 경우
            pr_warn("child terminated with unknown reason: %d\n", status);
            memset(&wd->usage, 0, sizeof(wd->usage));  // 리소스 사용량을 0으로 초기화
            ret = UFTRACE_EXIT_UNKNOWN;  // 알 수 없는 종료 처리
        }
    }
    else if (opts->keep_pid)
        memset(&wd->usage, 0, sizeof(wd->usage));  // 리소스 사용량을 0으로 설정
    else
        getrusage(RUSAGE_CHILDREN, &wd->usage);  // 자식 프로세스의 리소스 사용량 가져오기

    // 모든 기록 스레드 중지
    stop_all_writers();
    if (opts->kernel)
        stop_kernel_tracing(&wd->kernel);  // 커널 추적 중지

    // 기록 종료 시간을 가져옴
    clock_gettime(CLOCK_MONOTONIC, &wd->ts2);

    wd->status = status;  // 자식 프로세스 상태 저장
    return ret;  // 결과 반환
}

static void finish_writers(struct writer_data *wd, struct uftrace_opts *opts)
{
    // 모든 기록 스레드 작업을 완료하고 정리하는 함수
    int i;
    char *elapsed_time = get_child_time(&wd->ts1, &wd->ts2);  // 기록 시작 시간과 종료 시간 간의 경과 시간 계산

    // 옵션에 따라 경과 시간과 사용된 리소스 출력
    if (opts->time) {
        print_child_time(elapsed_time);  // 경과 시간 출력
        print_child_usage(&wd->usage);  // 사용된 시스템 및 사용자 시간 출력
    }

    // nop 옵션이 설정된 경우 경과 시간을 해제하고 함수 종료
    if (opts->nop) {
        free(elapsed_time);
        return;
    }

    // 파일 헤더 작성
    if (fill_file_header(opts, wd->status, &wd->usage, elapsed_time) < 0)
        pr_err("cannot generate data file");  // 파일 헤더 생성 실패 시 오류 출력

    free(elapsed_time);  // 경과 시간 메모리 해제

    // 공유 메모리에서 손실된 레코드가 있으면 경고 메시지 출력
    if (shmem_lost_count)
        pr_warn("LOST %d records\n", shmem_lost_count);

    // 모든 기록 스레드가 종료될 때까지 대기
    for (i = 0; i < opts->nr_thread; i++)
        pthread_join(wd->writers[i], NULL);  // 각 스레드 종료 대기
    free(wd->writers);  // 스레드 배열 메모리 해제
    close(thread_ctl[0]);  // 파이프 닫기

    // 공유 메모리의 남은 데이터 처리
    flush_shmem_list(opts->dirname, opts->bufsize);
    record_remaining_buffer(opts, wd->sock);  // 남은 기록 버퍼를 처리
    unlink_shmem_list();  // 공유 메모리 목록에서 파일 삭제
    free_tid_list();  // 스레드 ID 목록 해제

    // 커널 추적 종료
    if (opts->kernel)
        finish_kernel_tracing(&wd->kernel);
    // 성능 이벤트 추적 종료
    if (has_perf_event)
        finish_perf_record(&wd->perf);
}

static void copy_data_files(struct uftrace_opts *opts, const char *ext)
{
    // 특정 확장자를 가진 데이터 파일을 복사하는 함수
    char path[PATH_MAX];
    glob_t g;
    size_t i;

    // 복사할 파일 경로 패턴 생성
    snprintf(path, sizeof(path), "%s/*%s", opts->with_syms, ext);
    glob(path, GLOB_NOSORT, NULL, &g);  // 패턴에 맞는 파일 목록을 가져옴

    // 각 파일을 출력 디렉토리로 복사
    for (i = 0; i < g.gl_pathc; i++) {
        snprintf(path, sizeof(path), "%s/%s", opts->dirname, uftrace_basename(g.gl_pathv[i]));
        copy_file(g.gl_pathv[i], path);  // 파일 복사
    }

    globfree(&g);  // glob 결과 해제
}

static void write_symbol_files(struct writer_data *wd, struct uftrace_opts *opts)
{
    // 심볼 파일을 기록하고 전송하는 함수
    struct dlopen_list *dlib, *tmp;

    // nop 옵션이 설정된 경우 함수 종료
    if (opts->nop)
        return;

    // 빌드 ID 정보를 가진 맵 파일 추가
    update_session_maps(opts);

    // with_syms 옵션이 설정된 경우 심볼과 디버그 파일 복사
    if (opts->with_syms) {
        copy_data_files(opts, ".sym");  // .sym 파일 복사
        copy_data_files(opts, ".dbg");  // .dbg 파일 복사
        goto after_save;  // 이후 절차로 건너뜀
    }

    // 메인 실행 파일과 공유 라이브러리의 심볼을 로드
    load_session_symbols(opts);

    // 동적으로 로드된 라이브러리(dlopen)를 처리
    list_for_each_entry_safe(dlib, tmp, &dlopen_libs, list) {
        struct uftrace_sym_info dlib_sinfo = {
            .dirname = opts->dirname,
            .flags = SYMTAB_FL_ADJ_OFFSET,  // 심볼 테이블 오프셋 조정 플래그 설정
        };
        char build_id[BUILD_ID_STR_SIZE];  // 빌드 ID 저장

        read_build_id(dlib->libname, build_id, sizeof(build_id));  // 빌드 ID 읽기
        load_module_symtab(&dlib_sinfo, dlib->libname, build_id);  // 모듈 심볼 테이블 로드

        list_del(&dlib->list);  // 목록에서 삭제
        free(dlib->libname);  // 라이브러리 이름 메모리 해제
        free(dlib);  // dlopen 리스트 메모리 해제
    }

    // 모듈 심볼 테이블 저장 및 해제
    save_module_symtabs(opts->dirname);
    unload_module_symtabs();

after_save:
    // 호스트 옵션이 설정된 경우 데이터 전송
    if (opts->host) {
        int sock = wd->sock;

        // 각종 파일 전송
        send_task_file(sock, opts->dirname);  // 작업 파일 전송
        send_map_files(sock, opts->dirname);  // 맵 파일 전송
        send_sym_files(sock, opts->dirname);  // 심볼 파일 전송
        send_dbg_files(sock, opts->dirname);  // 디버그 파일 전송
        send_info_file(sock, opts->dirname);  // 정보 파일 전송

        if (opts->kernel)
            send_kernel_metadata(sock, opts->dirname);  // 커널 메타데이터 전송
        if (opts->event)
            send_event_file(sock, opts->dirname);  // 이벤트 파일 전송
        if (opts->logfile)
		{
			char *logfile_path = NULL;
			xasprintf(&logfile_path, "%s/%s", opts->dirname, opts->logfile);
            send_log_file(sock, opts->dirname, logfile_path);  // 로그 파일 전송
		}

        send_trace_end(sock);  // 추적 종료 메시지 전송
        close(sock);  // 소켓 닫기

        // 디렉토리 삭제
        remove_directory(opts->dirname);
    }
    // 루트 권한으로 실행된 경우 디렉토리 소유권 변경
    else if (geteuid() == 0)
        chown_directory(opts->dirname);
}
static int do_main_loop(int ready[], struct uftrace_opts *opts, int pid)
{
    // 메인 루프를 실행하는 함수. 기록을 시작하고, 기록 중 데이터를 읽으며, 종료 시 정리 작업을 수행.
    int ret;  // 반환 값
    struct writer_data wd;  // 기록 작업을 위한 데이터 구조체
    char *channel = NULL;  // 채널 파일 경로 저장용 문자열

    close(ready[0]);  // 준비 상태를 확인하는 파이프의 읽기 쪽을 닫음

    // nop 옵션이 설정된 경우 (실제 추적은 수행하지 않음)
    if (opts->nop) {
        setup_writers(&wd, opts);  // 기록 스레드를 설정
        start_tracing(&wd, opts, ready[1]);  // 기록 시작
        close(ready[1]);  // 준비 상태 파이프 닫기

        wait(NULL);  // 자식 프로세스가 종료될 때까지 대기
        uftrace_done = true;  // 추적 완료 플래그 설정

        ret = stop_tracing(&wd, opts);  // 기록 중지
        finish_writers(&wd, opts);  // 스레드 및 리소스 정리
        return ret;  // 반환 값 반환
    }

    // .channel 파일 경로 생성
    xasprintf(&channel, "%s/%s", opts->dirname, ".channel");

    wd.pid = pid;  // 프로세스 ID 설정
    wd.pipefd = open(channel, O_RDONLY | O_NONBLOCK);  // .channel 파일을 읽기 및 논블로킹 모드로 엶

    free(channel);  // 경로 문자열 메모리 해제
    if (wd.pipefd < 0)
        pr_err("cannot open pipe");  // 파이프 열기 실패 시 오류 메시지 출력

    // 시그널 트리거 옵션이 설정된 경우 메시지 출력
    if (opts->sig_trigger)
        pr_out("uftrace: install signal handlers to task %d\n", pid);

    setup_writers(&wd, opts);  // 기록 스레드를 설정
    start_tracing(&wd, opts, ready[1]);  // 기록 시작
    close(ready[1]);  // 준비 상태 파이프 닫기

    // 추적이 완료될 때까지 루프 실행
    while (!uftrace_done) {
        struct pollfd pollfd = {
            .fd = wd.pipefd,  // 파이프 파일 디스크립터 설정
            .events = POLLIN,  // 읽기 가능한 데이터가 있는지 확인
        };

        // 파이프에서 데이터가 올 때까지 기다림
        ret = poll(&pollfd, 1, 1000);  // 1초 타임아웃으로 poll 실행
        if (ret < 0 && errno == EINTR)  // 인터럽트가 발생한 경우 다시 시도
            continue;
        if (ret < 0)
            pr_err("error during poll");  // poll 중 오류 발생 시 오류 메시지 출력

        // 읽기 가능한 데이터가 있는 경우
        if (pollfd.revents & POLLIN)
            read_record_mmap(wd.pipefd, opts->dirname, opts->bufsize);  // 파이프에서 데이터를 읽어 mmap 기록

        // 에러나 연결 종료가 발생한 경우 루프 종료
        if (pollfd.revents & (POLLERR | POLLHUP))
            break;
    }

    // 기록 작업을 중지하고 결과를 처리
    ret = stop_tracing(&wd, opts);  // 기록 중지
    finish_writers(&wd, opts);  // 기록 스레드 및 리소스 정리

    // 심볼 파일 기록
    write_symbol_files(&wd, opts);
    return ret;  // 반환 값 반환
}
static int do_child_exec(int ready[], struct uftrace_opts *opts, int argc, char *argv[])
{
    // 자식 프로세스에서 실행할 프로그램을 설정하고 실행하는 함수
    uint64_t dummy;  // 부모 프로세스에서 신호를 받을 때 사용할 임시 변수
    char *shebang = NULL;  // 스크립트의 shebang(첫 번째 줄)을 저장할 포인터
    char dirpath[PATH_MAX];  // 작업 디렉토리의 절대 경로를 저장할 버퍼
    char exepath[PATH_MAX];  // 실행 파일 경로를 저장할 버퍼
    struct strv new_args = STRV_INIT;  // 새로운 인수 목록을 저장할 문자열 벡터
    bool is_python = false;  // 실행할 파일이 파이썬 스크립트인지 여부

    close(ready[1]);  // 준비 상태를 알리는 파이프의 쓰기 쪽을 닫음

    // 주소 공간 레이아웃 무작위화(ASLR)를 비활성화하는 옵션이 설정된 경우
    if (opts->no_randomize_addr) {
        if (personality(ADDR_NO_RANDOMIZE) < 0)
            pr_dbg("disabling ASLR failed\n");  // ASLR 비활성화 실패 시 디버그 메시지 출력
    }

    /*
     * 현재 작업 디렉토리가 변경될 수 있으므로 opts->dirname을 절대 경로로 변환하여
     * 문제를 방지함.
     */
    if (realpath(opts->dirname, dirpath) != NULL)
        opts->dirname = dirpath;  // 절대 경로로 변환

    // argv[0]에 접근할 수 있는지 확인
    if (access(argv[0], F_OK) == 0) {
        // 현재 디렉토리의 실행 파일이 PATH보다 우선시됨
        if (check_script_file(argv[0], exepath, sizeof(exepath)))
            shebang = exepath;  // 스크립트 파일인 경우 shebang 설정
    }
    else {
        // PATH 환경 변수에서 실행 파일을 검색
        struct strv path_names = STRV_INIT;
        char *path, *dir;
        int i, ret;

        strv_split(&path_names, getenv("PATH"), ":");  // PATH 환경 변수를 ":"로 분리
        strv_for_each(&path_names, dir, i) {
            xasprintf(&path, "%s/%s", dir, argv[0]);  // PATH 내에서 실행 파일 경로 생성
            ret = access(path, F_OK);  // 파일이 존재하는지 확인
            if (ret == 0 && check_script_file(path, exepath, sizeof(exepath)))
                shebang = exepath;  // 스크립트 파일인 경우 shebang 설정
            free(path);
            if (ret == 0)
                break;  // 실행 파일을 찾으면 루프 종료
        }
        strv_free(&path_names);  // 문자열 벡터 메모리 해제
    }

    // 스크립트 파일인 경우 shebang 처리
    if (shebang) {
        char *s, *p;
        int i;

#if defined(HAVE_LIBPYTHON2) || defined(HAVE_LIBPYTHON3)
        // 파이썬 스크립트인지 확인
        if (strstr(shebang, "python"))
            is_python = true;
#endif
        s = str_ltrim(shebang);  // shebang에서 앞의 공백 제거

        p = strchr(s, ' ');  // shebang에 공백이 있는지 확인
        if (p != NULL)
            *p++ = '\0';  // 공백을 기준으로 명령어와 인수 분리

        strv_append(&new_args, s);  // shebang의 명령어 추가
        if (p != NULL)
            strv_append(&new_args, p);  // 인수 추가

        // 파이썬 스크립트인 경우 추가 처리
        if (is_python) {
            strv_append(&new_args, "-m");  // uftrace 모듈을 로드하도록 설정
            strv_append(&new_args, "uftrace");
            if (!opts->libcall)
                setenv("UFTRACE_PY_LIBCALL", "NONE", 1);  // 라이브러리 호출 비활성화
            if (opts->nest_libcall)
                setenv("UFTRACE_PY_LIBCALL", "NESTED", 1);  // 중첩 라이브러리 호출 활성화
            opts->libcall = false;  // 파이썬 인터프리터에 대해 라이브러리 호출 비활성화
        }

        // 기존 인수들을 새로운 인수 목록에 추가
        for (i = 0; i < argc; i++)
            strv_append(&new_args, argv[i]);

        argc = new_args.nr;  // 새로운 인수 개수 설정
        argv = new_args.p;  // 새로운 인수 배열 설정
    }

    setup_child_environ(opts, argc, argv);  // 자식 프로세스의 환경 설정

    // 부모 프로세스가 준비될 때까지 대기
    if (read(ready[0], &dummy, sizeof(dummy)) != (ssize_t)sizeof(dummy))
        pr_err("waiting for parent failed");
    close(ready[0]);  // 파이프 닫기

    // 파이썬 스크립트인 경우 추가 환경 설정
    if (is_python) {
        char *python_path = NULL;

        if (getenv("PYTHONPATH"))
            python_path = strdup(getenv("PYTHONPATH"));  // 기존 PYTHONPATH를 복사

#ifdef INSTALL_LIB_PATH
        python_path = strjoin(python_path, INSTALL_LIB_PATH, ":");  // 설치된 라이브러리 경로 추가
#endif
        python_path = strjoin(python_path, "python", ":");  // 파이썬 모듈 경로 추가 (FIXME 필요)
        setenv("PYTHONPATH", python_path, 1);  // PYTHONPATH 환경 변수 설정
        free(python_path);  // 메모리 해제

        // .pyc 파일 생성을 방지 (일부 스크립트 실행 시 문제 발생 방지)
        setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
    }

    /*
     * 추적할 실행 파일 경로는 이미 절대 경로로 설정되어 있음.
     * execv를 사용해 프로그램을 실행 (execvp는 필요 없음).
     */
    execv(opts->exename, argv);  // 프로그램 실행
    abort();  // execv가 실패하면 프로그램 중지
}

int command_record(int argc, char *argv[], struct uftrace_opts *opts)
{
    // 기록 명령을 실행하는 함수. 자식 프로세스를 생성하고 추적 작업을 수행.
    int pid;  // 자식 프로세스의 PID
    int ready[2];  // 부모-자식 프로세스 간 통신을 위한 파이프
    int ret = -1;  // 반환 값 초기화
    char *channel = NULL;  // FIFO 통신 채널 경로를 저장할 포인터

    // 스크립트로 제공된 옵션을 적용
    if (opts->script_file)
        parse_script_opt(opts);  // 스크립트 옵션을 파싱

    check_binary(opts);  // 실행 파일이 유효한지 검사
    check_perf_event(opts);  // 성능 이벤트가 설정되었는지 확인

    // nop 옵션이 아닌 경우
    if (!opts->nop) {
        // 로그 파일이 없고 디렉토리 생성에 실패한 경우 -1 반환
        if (!opts->logfile && (create_directory(opts->dirname) < 0))
            return -1;

        // FIFO 통신 채널 생성
        xasprintf(&channel, "%s/%s", opts->dirname, ".channel");
        if (mkfifo(channel, 0600) < 0)
            pr_err("cannot create a communication channel");  // 채널 생성 실패 시 오류 출력
    }

    fflush(stdout);  // 표준 출력 버퍼 비우기

    // 부모-자식 간 통신을 위한 파이프 생성
    if (pipe(ready) < 0)
        pr_err("creating pipe failed");  // 파이프 생성 실패 시 오류 출력

    // 자식 프로세스를 생성 (fork)
    pid = fork();
    if (pid < 0)
        pr_err("cannot start child process");  // 자식 프로세스 생성 실패 시 오류 출력

    // 자식 프로세스의 코드 실행
    if (pid == 0) {
        // PID를 유지하는 옵션이 설정된 경우
        if (opts->keep_pid)
            ret = do_main_loop(ready, opts, getppid());  // 부모 프로세스의 PID로 메인 루프 실행
        else
            do_child_exec(ready, opts, argc, argv);  // 자식 프로세스에서 실행할 프로그램 실행

        // 채널이 생성되었을 경우 채널 제거
        if (channel) {
            unlink(channel);  // FIFO 파일 삭제
            free(channel);  // 메모리 해제
        }
        return ret;  // 자식 프로세스 종료
    }

    // 부모 프로세스에서 실행
    if (opts->keep_pid)
        do_child_exec(ready, opts, argc, argv);  // PID를 유지하는 경우 실행할 프로그램 실행
    else
        ret = do_main_loop(ready, opts, pid);  // 부모 프로세스에서 메인 루프 실행

    // 채널이 생성된 경우 채널 제거
    if (channel) {
        unlink(channel);  // FIFO 파일 삭제
        free(channel);  // 메모리 해제
    }
    return ret;  // 반환 값 반환
}
