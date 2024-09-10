/*
 * uftrace - Function (Graph) Tracer for Userspace
 *
 * Copyright (C) 2014-2018  LG Electronics
 * Author:  Namhyung Kim <namhyung@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "uftrace"

#include "uftrace.h"
#include "utils/script.h"
#include "utils/utils.h"
#include "version.h"

static const char uftrace_version[] = "uftrace " UFTRACE_VERSION;

static bool dbg_domain_set = false;

static bool parsing_default_opts = false;

/*
명령줄 옵션들을 / 열거형으로 정의합니다. 
각 옵션은 / 고유의 상수 값을 / 가지며, getopt 함수를 / 통해 파싱됩니다. 
*/
enum uftrace_short_options {
	OPT_flat = 301,
	OPT_no_libcall,
	OPT_symbols,
	OPT_logfile,
	OPT_force,
	OPT_task,
	OPT_no_merge,
	OPT_nop,
	OPT_time,
	OPT_max_stack,
	OPT_host,
	OPT_port,
	OPT_nopager,
	OPT_avg_total,
	OPT_avg_self,
	OPT_color,
	OPT_disabled,
	OPT_trace,
	OPT_demangle,
	OPT_dbg_domain,
	OPT_report,
	OPT_column_view,
	OPT_column_offset,
	OPT_bind_not,
	OPT_task_newline,
	OPT_chrome_trace,
	OPT_flame_graph,
	OPT_graphviz,
	OPT_sample_time,
	OPT_diff,
	OPT_format,
	OPT_sort_column,
	OPT_tid_filter,
	OPT_num_thread,
	OPT_no_comment,
	OPT_libmcount_single,
	OPT_rt_prio,
	OPT_kernel_bufsize,
	OPT_kernel_skip_out,
	OPT_kernel_full,
	OPT_kernel_only,
	OPT_list_event,
	OPT_run_cmd,
	OPT_opt_file,
	OPT_keep_pid,
	OPT_diff_policy,
	OPT_event_full,
	OPT_record,
	OPT_no_args,
	OPT_libname,
	OPT_match_type,
	OPT_no_randomize_addr,
	OPT_no_event,
	OPT_no_sched,
	OPT_no_sched_preempt,
	OPT_signal,
	OPT_srcline,
	OPT_with_syms,
	OPT_clock,
	OPT_usage,
	OPT_libmcount_path,
	OPT_mermaid,
	OPT_library_path,
	OPT_loc_filter,
};

/*
 clang-format 도구를 / 사용하지 않도록 설정합니다. 
 주로 코드 형식을 / 자동으로 정리하지 않기 위해 사용합니다. 
*/
/* clang-format off */

/*
 __used 속성은 / GCC 의 특정 속성으로, 변수가 / 사용되지 
않더라도 최적화 과정에서 제거되지 않도록 합니다.
static const char 는 / 상수를 / 정의하며, 이는 / 프로그램의 사용법을 / 
저장합니다. 
*/

/*
• 프로그램의 간단한 설명을 / 문자열로 정의합니다. 
*/
__used static const char uftrace_usage[] =
" uftrace -- function (graph) tracer for userspace\n"
"\n"

/*
 사용법을 / 설명하는 / 문자열입니다. 
*/
" usage: uftrace [COMMAND] [OPTION...] [<program>]\n"
"\n"
/*
• 명령어 목록을 / 소개하는 / 문자열입니다. 
*/
" COMMAND:\n"
"   record          Run a program and saves the trace data\n"
"   replay          Show program execution in the trace data\n"
"   report          Show performance statistics in the trace data\n"
"   live            Do record and replay in a row (default)\n"
"   info            Show system and program info in the trace data\n"
"   dump            Show low-level trace data\n"
"   recv            Save the trace data from network\n"
"   graph           Show function call graph in the trace data\n"
"   script          Run a script for recorded trace data\n"
"   tui             Show text user interface for graph and report\n"
"\n";

/*
 __used 속성을 / 사용하여 / 상수 문자열 uftrace_help 를 / 
정의합니다. 이 문자열은 / 옵션들에 / 대한 도움말을 / 
저장합니다. 
*/
__used static const char uftrace_help[] =
" OPTION:\n"
"      --avg-self             Show average/min/max of self function time\n"
"      --avg-total            Show average/min/max of total function time\n"
"  -a, --auto-args            Show arguments and return value of known functions\n"
"  -A, --argument=FUNC@arg[,arg,...]\n"
"                             Show function arguments\n"
"  -b, --buffer=SIZE          Size of tracing buffer (default: "
	stringify(SHMEM_BUFFER_SIZE_KB) "K)\n"
"      --chrome               Dump recorded data in chrome trace format\n"
"      --clock                Set clock source for timestamp (default: mono)\n"
"      --color=SET            Use color for output: yes, no, auto (default: auto)\n"
"      --column-offset=DEPTH  Offset of each column (default: "
	stringify(OPT_COLUMN_OFFSET) ")\n"
"      --column-view          Print tasks in separate columns\n"
"  -C, --caller-filter=FUNC   Only trace callers of those FUNCs\n"
"  -d, --data=DATA            Use this DATA instead of uftrace.data\n"
"      --debug-domain=DOMAIN  Filter debugging domain\n"
"      --demangle=TYPE        C++ symbol demangling: full, simple, no\n"
"                             (default: simple)\n"
"      --diff=DATA            Report differences\n"
"      --diff-policy=POLICY   Control diff report policy\n"
"                             (default: 'abs,compact,no-percent')\n"
"      --disable              Start with tracing disabled (deprecated)\n"
"  -D, --depth=DEPTH          Trace functions within DEPTH\n"
"  -e, --estimate-return      Use only entry record type for safety\n"
"      --event-full           Show all events outside of function\n"
"  -E, --Event=EVENT          Enable EVENT to save more information\n"
"      --flame-graph          Dump recorded data in FlameGraph format\n"
"      --flat                 Use flat output format\n"
"      --force                Trace even if executable is not instrumented\n"
"      --format=FORMAT        Use FORMAT for output: normal, html (default: normal)\n"
"  -f, --output-fields=FIELD  Show FIELDs in the replay or graph output\n"
"  -F, --filter=FUNC          Only trace those FUNCs\n"
"  -g  --agent                Start an agent in mcount to listen to commands\n"
"      --graphviz             Dump recorded data in DOT format\n"
"  -H, --hide=FUNC            Hide FUNCs from trace\n"
"      --host=HOST            Send trace data to HOST instead of write to file\n"
"  -k, --kernel               Trace kernel functions also (if supported)\n"
"      --keep-pid             Keep same pid during execution of traced program\n"
"      --kernel-buffer=SIZE   Size of kernel tracing buffer (default: 1408K)\n"
"      --kernel-full          Show kernel functions outside of user\n"
"      --kernel-only          Dump kernel data only\n"
"      --kernel-skip-out      Skip kernel functions outside of user (deprecated)\n"
"  -K, --kernel-depth=DEPTH   Trace kernel functions within DEPTH\n"
"      --libmcount-single     Use single thread version of libmcount\n"
"      --list-event           List available events\n"
"  -L, --loc-filter=LOCATION  Only trace functions in the source LOCATION\n"
"      --logfile=FILE         Save log messages to this file\n"
"  -l, --nest-libcall         Show nested library calls\n"
"      --libname              Show libname name with symbol name\n"
"      --libmcount-path=PATH  Load libmcount libraries from this PATH\n"
"      --match=TYPE           Support pattern match: regex, glob (default:\n"
"                             regex)\n"
"      --max-stack=DEPTH      Set max stack depth to DEPTH (default: "
	stringify(OPT_RSTACK_MAX) ")\n"
"      --no-args              Do not show arguments and return value\n"
"      --no-comment           Don't show comments of returned functions\n"
"      --no-event             Disable (default) events\n"
"      --no-sched             Disable schedule events\n"
"      --no-sched-preempt     Hide pre-emptive schedule event\n"
"                             but show regular(sleeping) schedule event\n"
"      --no-libcall           Don't trace library function calls\n"
"      --no-merge             Don't merge leaf functions\n"
"      --no-pager             Do not use pager\n"
"      --no-pltbind           Do not bind dynamic symbols (LD_BIND_NOT)\n"
"      --no-randomize-addr    Disable ASLR (Address Space Layout Randomization)\n"
"      --nop                  No operation (for performance test)\n"
"      --num-thread=NUM       Create NUM recorder threads\n"
"  -N, --notrace=FUNC         Don't trace those FUNCs\n"
"      --opt-file=FILE        Read command-line options from FILE\n"
"  -p  --pid=PID              PID of an interactive mcount instance\n"
"      --port=PORT            Use PORT for network connection (default: "
	stringify(UFTRACE_RECV_PORT) ")\n"
"  -P, --patch=FUNC           Apply dynamic patching for FUNCs\n"
"      --record               Record a new trace data before running command\n"
"      --report               Show live report\n"
"      --rt-prio=PRIO         Record with real-time (FIFO) priority\n"
"  -r, --time-range=TIME~TIME Show output within the TIME(timestamp or elapsed time)\n"
"                             range only\n"
"      --run-cmd=CMDLINE      Command line that want to execute after tracing\n"
"                             data received\n"
"  -R, --retval=FUNC@retval   Show function return value\n"
"      --sample-time=TIME     Show flame graph with this sampling time\n"
"      --signal=SIG@act[,act,...]   Trigger action on those SIGnal\n"
"      --sort-column=INDEX    Sort diff report on column INDEX (default: 2)\n"
"      --srcline              Enable recording source line info\n"
"      --symbols              Print symbol tables\n"
"  -s, --sort=KEY[,KEY,...]   Sort reported functions by KEYs (default: "
	stringify(OPT_SORT_COLUMN) ")\n"
"  -S, --script=SCRIPT        Run a given SCRIPT in function entry and exit\n"
"  -t, --time-filter=TIME     Hide small functions run less than the TIME\n"
"      --task                 Show task info instead\n"
"      --task-newline         Interleave a newline when task is changed\n"
"      --tid=TID[,TID,...]    Only replay those tasks\n"
"      --time                 Print time information\n"
"      --trace=STATE          Set the recording state: on, off (default: on)\n"
"  -T, --trigger=FUNC@act[,act,...]\n"
"                             Trigger action on those FUNCs\n"
"  -U, --unpatch=FUNC         Don't apply dynamic patching for FUNCs\n"
"  -v, --debug                Print debug messages\n"
"      --verbose              Print verbose (debug) messages\n"
"      --with-syms=DIR        Use symbol files in the DIR\n"
"  -W, --watch=POINT          Watch and report POINT if it's changed\n"
"  -Z, --size-filter=SIZE     Apply dynamic patching for functions bigger than SIZE\n"
"  -h, --help                 Give this help list\n"
"      --usage                Give a short usage message\n"
"  -V, --version              Print program version\n"
"\n"
" Try `man uftrace [COMMAND]' for more information.\n"
"\n";

/*
• __used 속성으로 지정된 uftrace_footer 상수 문자열을 / 
정의합니다. 이 문자열은 / 프로그램의 추가 / 도움말 정보를 /
제공합니다. 
*/
__used static const char uftrace_footer[] =
" Try `uftrace --help' or `man uftrace [COMMAND]' for more information.\n"
"\n";

/*
• 단일 문자 옵션을 / 정의하는 / 문자열입니다. getopt 함수가
이 문자열을 / 사용하여 / 명령줄 옵션을 / 파싱합니다. 
*/
static const char uftrace_shopts[] =
	"+aA:b:C:d:D:eE:f:F:ghH:kK:lL:N:p:P:r:R:s:S:t:T:U:vVW:Z:";

/*
 매크로 정의로, name 옵션이 필수 인수를 / 가지는 / 
구조체 option 을 / 생성합니다. 
*/
#define REQ_ARG(name, shopt) { #name, required_argument, 0, shopt }

/*
• 매크로 정의로, name 옵션이 인수를 / 가지지 않는 / 
구조체 option 을 / 생성합니다. 
*/
#define NO_ARG(name, shopt)  { #name, no_argument, 0, shopt }

/*
 명령줄 옵션을 / 정의하는 / option 구조체 배열을 / 선언합니다. 
*/
static const struct option uftrace_options[] = {

	/*
	 libmcount-path 옵션을 / 정의합니다.
	*/
	REQ_ARG(libmcount-path, OPT_libmcount_path),

	/*
	library-path 옵션을 / 정의합니다.
	*/
	REQ_ARG(library-path, OPT_libmcount_path),
	REQ_ARG(filter, 'F'),
	REQ_ARG(notrace, 'N'),
	REQ_ARG(depth, 'D'),
	REQ_ARG(time-filter, 't'),
	REQ_ARG(caller-filter, 'C'),
	REQ_ARG(argument, 'A'),
	REQ_ARG(trigger, 'T'),
	REQ_ARG(retval, 'R'),
	NO_ARG(auto-args, 'a'),
	NO_ARG(no-args, OPT_no_args),
	REQ_ARG(patch, 'P'),
	REQ_ARG(unpatch, 'U'),
	REQ_ARG(size-filter, 'Z'),
	NO_ARG(debug, 'v'),
	NO_ARG(verbose, 'v'),
	REQ_ARG(debug-domain, OPT_dbg_domain),
	NO_ARG(force, OPT_force),
	REQ_ARG(data, 'd'),
	NO_ARG(flat, OPT_flat),
	NO_ARG(symbols, OPT_symbols),
	REQ_ARG(buffer, 'b'),
	REQ_ARG(logfile, OPT_logfile),
	NO_ARG(task, OPT_task),
	REQ_ARG(tid, OPT_tid_filter),
	NO_ARG(no-merge, OPT_no_merge),
	NO_ARG(nop, OPT_nop),
	NO_ARG(time, OPT_time),
	REQ_ARG(max-stack, OPT_max_stack),
	REQ_ARG(host, OPT_host),
	REQ_ARG(port, OPT_port),
	NO_ARG(no-pager, OPT_nopager),
	REQ_ARG(sort, 's'),
	NO_ARG(avg-total, OPT_avg_total),
	NO_ARG(avg-self, OPT_avg_self),
	REQ_ARG(color, OPT_color),
	NO_ARG(disable, OPT_disabled),
	REQ_ARG(trace, OPT_trace),
	REQ_ARG(demangle, OPT_demangle),
	NO_ARG(record, OPT_record),
	NO_ARG(report, OPT_report),
	NO_ARG(column-view, OPT_column_view),
	REQ_ARG(column-offset, OPT_column_offset),
	NO_ARG(no-pltbind, OPT_bind_not),
	NO_ARG(task-newline, OPT_task_newline),
	NO_ARG(chrome, OPT_chrome_trace),
	NO_ARG(graphviz, OPT_graphviz),
	NO_ARG(flame-graph, OPT_flame_graph),
	NO_ARG(mermaid, OPT_mermaid),
	REQ_ARG(sample-time, OPT_sample_time),
	REQ_ARG(diff, OPT_diff),
	REQ_ARG(format, OPT_format),
	REQ_ARG(sort-column, OPT_sort_column),
	REQ_ARG(num-thread, OPT_num_thread),
	NO_ARG(no-comment, OPT_no_comment),
	NO_ARG(libmcount-single, OPT_libmcount_single),
	REQ_ARG(rt-prio, OPT_rt_prio),
	NO_ARG(kernel, 'k'),
	REQ_ARG(kernel-depth, 'K'),
	REQ_ARG(kernel-buffer, OPT_kernel_bufsize),
	NO_ARG(kernel-skip-out, OPT_kernel_skip_out),
	NO_ARG(kernel-full, OPT_kernel_full),
	NO_ARG(kernel-only, OPT_kernel_only),
	REQ_ARG(output-fields, 'f'),
	REQ_ARG(time-range, 'r'),
	REQ_ARG(Event, 'E'),
	NO_ARG(no-event, OPT_no_event),
	NO_ARG(no-sched, OPT_no_sched),
	NO_ARG(no-sched-preempt, OPT_no_sched_preempt),
	NO_ARG(list-event, OPT_list_event),
	REQ_ARG(run-cmd, OPT_run_cmd),
	REQ_ARG(opt-file, OPT_opt_file),
	NO_ARG(keep-pid, OPT_keep_pid),
	REQ_ARG(script, 'S'),
	REQ_ARG(diff-policy, OPT_diff_policy),
	NO_ARG(event-full, OPT_event_full),
	NO_ARG(no-libcall, OPT_no_libcall),
	NO_ARG(nest-libcall, 'l'),
	NO_ARG(libname, OPT_libname),
	REQ_ARG(match, OPT_match_type),
	NO_ARG(no-randomize-addr, OPT_no_randomize_addr),
	REQ_ARG(watch, 'W'),
	REQ_ARG(signal, OPT_signal),
	NO_ARG(srcline, OPT_srcline),
	REQ_ARG(hide, 'H'),
	REQ_ARG(loc-filter, OPT_loc_filter),
	REQ_ARG(loc-filter-warning, 'L'), /* the long option is dummy, will change later */
	REQ_ARG(clock, OPT_clock),
	NO_ARG(help, 'h'),
	NO_ARG(usage, OPT_usage),
	NO_ARG(version, 'V'),
	NO_ARG(estimate-return, 'e'),
	REQ_ARG(with-syms, OPT_with_syms),
	NO_ARG(agent, 'g'),
	REQ_ARG(pid, 'p'),
	{ 0 }
};
/* clang-format on */
/*
 clang-format 도구의 자동 코드 형식을 / 다시 활성화합니다.
*/

/*
 이전에 / 정의된 REQ_ARG 와 NO_ARG 매크로를 / 해제합니다. 
 이는 / 매크로 재정의를 / 방지하기 위해 사용됩니다. 
*/
#undef REQ_ARG
#undef NO_ARG

/*
 parse_size 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
문자열로 표현된 크기를 / 파싱하여 / 바이트 단위의 값을 / 
반환합니다. 
*/
static unsigned long parse_size(char *str)
{
	/*
	• size 변수는 / 파싱된 크기를 / 저장하고, 
	unit 변수는 / 크기 	문자열에서 단위를 / 가리킵니다. 
	*/
	unsigned long size;
	char *unit;

	/*
	• strtoul 함수를 / 사용하여 / 문자열 str 을 
	/ unsigned long 타입으로 변환합니다.
	 unit 포인터는 / 숫자가 / 아닌 첫 번째 문자를 / 가리킵니다. 
	*/
	size = strtoul(str, &unit, 0);

	/*
	• unit 이 가리키는 / 문자의 값을 / 기준으로 분기문을 / 
	시작합니다. 
	*/
	switch (*unit) {

	/*
	 unit 이 널 문자일 경우 (즉, 단위가 / 없을 / 경우) 아무 작업도 
	하지 않습니다. 
	*/
	case '\0':
		break;

	/*
	• unit 이 'k' 또는 / 'K'일 경우 size 를 / 1024(2의 10 제곱)로 
	곱합니다. 이는 / 킬로바이트 단위를 / 바이트로 변환하는 / 
	것입니다. 
	*/	
	case 'k':
	case 'K':
		size <<= 10;
		break;

	/*
	 unit 이 'm' 또는 / 'M'일 경우 size 를 / 1048576(2 의 20 제곱)로 
	곱합니다. 이는 / 메가바이트 단위를 / 바이트로 변환하는 / 
	것입니다. 
	*/
	case 'm':
	case 'M':
		size <<= 20;
		break;

	/*
	unit 이 'g' 또는 / 'G'일 경우 size 를 / 1073741824(2 의 
	30 제곱)로 곱합니다. 이는 / 기가바이트 단위를 / 바이트로 
	변환하는 / 것입니다. 
	*/	
	case 'g':
	case 'G':
		size <<= 30;
		break;

	/*
	 unit 이 알려진 단위 문자가 / 아닌 경우, 오류 메시지를 / 
	출력하고 size 를 / 0 으로 설정합니다. 
	*/
	default:
		pr_use("invalid size: %s\n", str);
		size = 0;
		break;
	}

	//  변환된 크기를 / 반환합니다. 
	return size;
}

/*
• opt_add_string 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 두 
개의 문자열을 / 세미콜론으로 구분하여 / 결합합니다. 
*/
static char *opt_add_string(char *old_opt, char *new_opt)
{
	/*
	 strjoin 함수를 / 호출하여 / old_opt 와 new_opt 를 / 세미콜론으로 
	구분하여 / 결합한 새 문자열을 / 반환합니다. 
	*/
	return strjoin(old_opt, new_opt, ";");
}


/*
 opt_add_prefix_string 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
새로운 옵션 문자열에 / 접두사를 / 추가하고 기존 옵션 
문자열과 결합합니다. 
*/
static char *opt_add_prefix_string(char *old_opt, char *prefix, char *new_opt)
{
	/*
	 xstrdup 함수를 / 사용하여 / prefix 문자열의 복사본을 / 만들고, 
	이를 / new_opt 과 결합하여 / 새 문자열을 / 
	생성합니다. strjoin 함수는 / 두 문자열을 / 결합하는 / 
	함수입니다. 
	*/
	new_opt = strjoin(xstrdup(prefix), new_opt, "");

	// old_opt 가 / NULL이 아닌 경우를 / 검사합니다. 
	if (old_opt) {

		/*
		 old_opt 와 new_opt 을 / 세미콜론으로 구분하여 / 결합한 새 
		문자열을 / 생성합니다. 
		*/
		old_opt = strjoin(old_opt, new_opt, ";");

		/*
		 new_opt 에 / 할당된 메모리를 / 해제합니다. 
		*/
		free(new_opt);

		// new_opt 에 / old_opt 의 값을 / 대입합니다. 
		new_opt = old_opt;
	}
	// 결합된 문자열을 / 반환합니다. 
	return new_opt;
}

/*
• "true" 값을 / 나타내는 / 문자열 배열을 / 정의합니다. 이 
배열은 / 다양한 형식의 true 값을 / 포함합니다. 
*/
static const char *true_str[] = {
	"true", "yes", "on", "y", "1",
};

/*
 "false" 값을 / 나타내는 / 문자열 배열을 / 정의합니다. 이 
배열은 / 다양한 형식의 false 값을 / 포함합니다. 
*/
static const char *false_str[] = {
	"false", "no", "off", "n", "0",
};

/*
 parse_color 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 문자열 
인자를 / 받아 색상 설정 값을 / 반환합니다. 
*/
static enum color_setting parse_color(char *arg)
{
	// 반복문에서 사용할 변수 i 를 / 선언합니다. 
	size_t i;

	/*
	 true_str 배열의 각 요소를 / 반복합니다. 
	 ARRAY_SIZE 매크로는 / 배열의 크기를 / 반환합니다. 
	*/
	for (i = 0; i < ARRAY_SIZE(true_str); i++) {

		/*
		 arg 와 true_str 배열의 현재 요소를 / 비교하여 / 
		일치하면 COLOR_ON 값을 / 반환합니다. 
		*/
		if (!strcmp(arg, true_str[i]))
			return COLOR_ON;
	}

	// false_str 배열의 각 요소를 / 반복합니다. 
	for (i = 0; i < ARRAY_SIZE(false_str); i++) {

		/*
		arg 와 false_str 배열의 현재 요소를 / 비교하여 / 
		일치하면 COLOR_OFF 값을 / 반환합니다. 
		*/
		if (!strcmp(arg, false_str[i]))
			return COLOR_OFF;
	}

	//  arg 가 / "auto"와 일치하면 COLOR_AUTO 값을 / 반환합니다. 
	if (!strcmp(arg, "auto"))
		return COLOR_AUTO;
	
	// 일치하는 / 값이 없으면 COLOR_UNKNOWN 값을 / 반환합니다. 
	return COLOR_UNKNOWN;
}


/*
 parse_demangle 라는 / 정적 함수를 / 정의합니다. 
이 함수는 / 문자열 인자를 / 받아 디망글링 옵션 값을 / 반환합니다. 
*/
static int parse_demangle(char *arg)
{
	//  반복문에서 사용할 변수 i 를 / 선언합니다. 
	size_t i;

	/*
	arg 가 / "simple"과 일치하면 DEMANGLE_SIMPLE 값을 / 반환합니다. 
	*/
	if (!strcmp(arg, "simple"))
		return DEMANGLE_SIMPLE;

	/*
	arg 가 / "full"과 일치하면 support_full_demangle 함수를 / 호출하여 
	/ 전체 디망글링을 / 지원하는지 확인합니다. 
	지원하면 DEMANGLE_FULL 값을 / 반환하고, 지원하지 
	않으면 DEMANGLE_NOT_SUPPORTED 값을 / 반환합니다. 
	*/
	if (!strcmp(arg, "full")) {
		if (support_full_demangle())
			return DEMANGLE_FULL;
		return DEMANGLE_NOT_SUPPORTED;
	}

	/*
	 false_str 배열의 각 요소를 / 반복합니다. arg 가 / 
	false_str 배열의 현재 요소와 일치하면 DEMANGLE_NONE 값을 / 
	반환합니다. 
	*/
	for (i = 0; i < ARRAY_SIZE(false_str); i++) {
		if (!strcmp(arg, false_str[i]))
			return DEMANGLE_NONE;
	}

	// 일치하는 / 값이 없으면 DEMANGLE_ERROR 값을 / 반환합니다. 
	return DEMANGLE_ERROR;
}

/*
• parse_debug_domain 라는 / 정적 함수를 / 정의합니다. 
이 함수는 /디버그 도메인을 / 파싱하여 / 설정합니다. 
인자로는 / 문자열 arg 를 / 받습니다. 
*/
static void parse_debug_domain(char *arg)
{
	/*
	strv 라는 / 구조체 변수를 / 초기화합니다. 
	STRV_INIT 은 / strv 를 / 초기화하는 / 매크로 또는 / 상수로 보입니다. 
	*/
	struct strv strv = STRV_INIT;
	
	/*
	 tok 와 tmp 라는 / 포인터 변수를 / 선언합니다. 
	 이는 / 문자열 토큰을 / 가리키는 / 데 사용됩니다. 
	*/
	char *tok, *tmp;

	// 반복문에서 사용할 변수 i 를 / 선언합니다. 
	int i;

	/*
	 strv_split 함수를 / 사용하여 / arg 문자열을 / 쉼표(,)를 / 
	기준으로 나누고, 결과를 / strv 구조체에 / 저장합니다. 
	*/
	strv_split(&strv, arg, ",");

	/*
	 strv 의 각 요소를 / 반복합니다.
	  strv_for_each 매크로는 / strv 의 각 문자열을 / 순회합니다. 
	*/
	strv_for_each(&strv, tok, i) {

		// 디버그 레벨을 / 나타내는 / 변수 level 을 / 초기화합니다.
		int level = -1;

		/*
		 strchr 함수를 / 사용하여 / tok 문자열에서 콜론(:) 문자를 / 
		찾습니다. 콜론이 없으면 tmp 는 / NULL 이 됩니다. 
		*/
		tmp = strchr(tok, ':');

		/*
		 tmp 가 / NULL 이 아니면, 즉 콜론이 있으면, 콜론을 / 널 문자로 
		대체하고 tmp 를 / 증가시켜 콜론 다음 문자를 / 가리키게 
		합니다. 그런 다음 strtol 함수를 / 사용하여 / 콜론 다음 
		문자열을 / 정수로 변환하여 / level 변수에 / 저장합니다. 
		*/
		if (tmp) {
			*tmp++ = '\0';
			level = strtol(tmp, NULL, 0);
		}


		/*
		 tok 문자열의 값을 / 비교하여 / 해당하는 / 디버그 도메인 
		인덱스에 / level 값을 / 설정합니다. "ftrace"는 / 이전 
		버전과의 호환성을 / 위해 사용됩니다. 
		*/
		if (!strcmp(tok, "ftrace")) /* for backward compatibility */
			dbg_domain[DBG_UFTRACE] = level;
		else if (!strcmp(tok, "uftrace"))
			dbg_domain[DBG_UFTRACE] = level;
		else if (!strcmp(tok, "symbol"))
			dbg_domain[DBG_SYMBOL] = level;
		else if (!strcmp(tok, "demangle"))
			dbg_domain[DBG_DEMANGLE] = level;
		else if (!strcmp(tok, "filter"))
			dbg_domain[DBG_FILTER] = level;
		else if (!strcmp(tok, "fstack"))
			dbg_domain[DBG_FSTACK] = level;
		else if (!strcmp(tok, "session"))
			dbg_domain[DBG_SESSION] = level;
		else if (!strcmp(tok, "kernel"))
			dbg_domain[DBG_KERNEL] = level;
		else if (!strcmp(tok, "mcount"))
			dbg_domain[DBG_MCOUNT] = level;
		else if (!strcmp(tok, "plthook"))
			dbg_domain[DBG_PLTHOOK] = level;
		else if (!strcmp(tok, "dynamic"))
			dbg_domain[DBG_DYNAMIC] = level;
		else if (!strcmp(tok, "event"))
			dbg_domain[DBG_EVENT] = level;
		else if (!strcmp(tok, "script"))
			dbg_domain[DBG_SCRIPT] = level;
		else if (!strcmp(tok, "dwarf"))
			dbg_domain[DBG_DWARF] = level;
		else if (!strcmp(tok, "wrap"))
			dbg_domain[DBG_WRAP] = level;
	}

	/*
	 dbg_domain_set 변수를 / true 로 설정하여 / 디버그 도메인이 
	설정되었음을 / 나타냅니다. 
	*/
	dbg_domain_set = true;

	/*
	strv_free 함수를 / 사용하여 / strv 구조체에 / 할당된 메모리를 / 
	해제합니다. 
	*/
	strv_free(&strv);
}

/*
• has_time_unit 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
문자열의 마지막 문자가 / 알파벳인지 확인하여 / 시간 단위가 / 
있는지를 / 판단합니다. 
*/
static bool has_time_unit(const char *str)
{
	/*
	• 문자열의 마지막 문자가 / 알파벳인지 확인합니다. 
	알파벳이면 true 를 / 반환하고, 그렇지 않으면 false 를 / 
	반환합니다. 
	*/
	if (isalpha(str[strlen(str) - 1]))
		return true;
	else
		return false;
}

/*
parse_any_timestamp 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
문자열을 / 파싱하여 / 타임스탬프를 / 반환합니다. elapsed 는 / 
경과 시간을 / 나타내는 / 플래그입니다. 
*/
static uint64_t parse_any_timestamp(char *str, bool *elapsed)
{
	// 문자열이 빈 문자열이면 0 을 / 반환합니다. 
	if (*str == '\0')
		return 0;

	/*
	문자열에 / 시간 단위가 / 있으면, elapsed 를 / true 로 
	설정하고 parse_time 함수를 / 호출하여 / 시간을 / 파싱합니다. 
	*/
	if (has_time_unit(str)) {
		*elapsed = true;
		return parse_time(str, 3);
	}
	/*
	 그렇지 않으면 elapsed 를 / false 로 설정하고 parse_timestamp 함수를 
	/ 호출하여 / 타임스탬프를 / 파싱합니다. 
	*/
	*elapsed = false;
	return parse_timestamp(str);
}

/*
• parse_time_range 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
시간 범위를 / 파싱하여 / uftrace_time_range 구조체에 / 
저장합니다. 
*/
static bool parse_time_range(struct uftrace_time_range *range, char *arg)
{
	/*
	 문자열 포인터 str 과 pos 를 / 선언합니다. 
	*/
	char *str, *pos;


	/*
	 xstrdup 함수를 / 사용하여 / arg 문자열을 / 복사합니다. 
	*/
	str = xstrdup(arg);

	/*
	• strchr 함수를 / 사용하여 / str 문자열에서 '~' 문자를 / 
	찾습니다. 문자가 / 없으면 str 을 / 해제하고 false 를 / 
	반환합니다. 
	*/
	pos = strchr(str, '~');
	if (pos == NULL) {
		free(str);
		return false;
	}

	/*
	 '~' 문자를 / 널 문자로 대체하고, pos 를 / 증가시켜 
	 다음 문자를 / 가리키게 합니다. 
	*/
	*pos++ = '\0';

	/*
	• parse_any_timestamp 함수를 / 사용하여 / 시작 시간과 종료 시간을 / 
	파싱하여 / range 구조체에 / 저장합니다. 
	*/
	range->start = parse_any_timestamp(str, &range->start_elapsed);
	range->stop = parse_any_timestamp(pos, &range->stop_elapsed);

	//• str 을 / 해제하고 true 를 / 반환합니다. 
	free(str);
	return true;
}

/*
 remove_trailing_slash 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
경로 문자열의 끝에 / 있는 / 슬래시를 / 제거합니다. 
*/
static char *remove_trailing_slash(char *path)
{
	//  path 문자열의 길이를 / 계산하여 / len 변수에 / 저장합니다.
	size_t len = strlen(path);

	/*
	path 문자열의 마지막 문자가 / 슬래시('/')이면, 이를 / 널 
	문자('\0')로 대체합니다. 
	*/
	if (path[len - 1] == '/')
		path[len - 1] = '\0';

	// 수정된 path 문자열을 / 반환합니다. 
	return path;
}

/*
 is_libmcount_directory 라는 / 정적 함수를 / 정의합니다. 이 함수는 
/ 주어진 경로가 / libmcount 디렉토리 또는 / libmcount.so 파일을 / 
포함하는지 확인합니다. 
*/
static bool is_libmcount_directory(const char *path)
{
	/*
	 디렉토리 스트림을 / 나타내는 / 포인터 dp 를 / 선언하고 
	NULL 로 초기화합니다. 
	*/
	DIR *dp = NULL;

	/*
	 디렉토리 항목을 / 나타내는 / 구조체 포인터 ent 와 반환 값을 / 
	저장할 변수 ret 을 / 선언하고 ret 을 / false 로 초기화합니다. 
	*/
	struct dirent *ent;
	int ret = false;

	/*
	opendir 함수를 / 사용하여 / 주어진 경로의 디렉토리를 / 엽니다. 
	디렉토리를 / 열지 못하면 false 를 / 반환합니다. 
	*/
	dp = opendir(path);
	if (dp == NULL)
		return false;

	/*
	 readdir 함수를 / 사용하여 / 디렉토리의 항목을 / 하나씩 
	읽습니다. 항목이 없으면 NULL 을 / 반환합니다. 
	*/
	while ((ent = readdir(dp)) != NULL) {

		/*
		 디렉토리 항목이 libmcount 디렉토리거나 libmcount.so 파일인 
		경우 ret 을 / true 로 설정하고 반복문을 / 종료합니다. 
		*/
		if ((ent->d_type == DT_DIR && !strcmp(ent->d_name, "libmcount")) ||
		    ((ent->d_type == DT_LNK || ent->d_type == DT_REG) &&
		     !strcmp(ent->d_name, "libmcount.so"))) {
			ret = true;
			break;
		}
	}
	/*
	 closedir 함수를 / 사용하여 / 열려 있는 / 디렉토리를 / 
	닫습니다. 
	*/
	closedir(dp);

	// • ret 값을 / 반환합니다. 
	return ret;
}

/*
parse_option 이라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
명령줄 옵션을 / 파싱하여 / uftrace_opts 구조체에 / 저장합니다. 
*/
static int parse_option(struct uftrace_opts *opts, int key, char *arg)
{
	//  문자열 포인터 pos 를 / 선언합니다. 
	char *pos;


	//  key 값에 / 따라 분기문을 / 시작합니다. 
	switch (key) {
	
	/*
	 key 가 / 'F'일 경우, opts->filter 에 / arg 문자열을 / 
	추가합니다. 
	*/
	case 'F':
		opts->filter = opt_add_string(opts->filter, arg);
		break;

	/*
	key 가 / 'N'일 경우, opts->filter 에 / arg 문자열 앞에 / '!' 
	접두사를 / 붙여 추가합니다. 
	*/
	case 'N':
		opts->filter = opt_add_prefix_string(opts->filter, "!", arg);
		break;

	/*
	 key 가 / 'T'일 경우, opts->trigger 에 / arg 문자열을 / 
	추가합니다. 
	*/
	case 'T':
		opts->trigger = opt_add_string(opts->trigger, arg);
		break;

	/*
	key 가 / 'D'일 경우, arg 문자열을 / 정수로 변환하여 / 
	opts->depth 에 / 저장합니다. 변환된 값이 유효한 범위 내에 / 있지 
	않으면, 오류 메시지를 / 출력하고 기본 깊이 값으로 
	설정합니다. 
	*/
	case 'D':
		opts->depth = strtol(arg, NULL, 0);
		if (opts->depth <= 0 || opts->depth >= OPT_DEPTH_MAX) {
			pr_use("invalid depth given: %s (ignoring..)\n", arg);
			opts->depth = OPT_DEPTH_DEFAULT;
		}
		break;
	/*
	• key 가 / 'C'일 경우, opts->caller 에 / arg 문자열을 / 
	추가합니다. 호출자 필터가 / 특정 함수에 / 집중되므로 스케줄 
	이벤트를 / 표시하는 / 것을 / 비활성화합니다. 
	*/
	case 'C':
		opts->caller = opt_add_string(opts->caller, arg);
		/*
		 * caller filter focuses onto a given function,
		 * displaying sched event with it is annoying.
		 */
		opts->no_sched = true;
		break;

	// key 가 / 'H'일 경우, opts->hide 에 / arg 문자열을 / 추가합니다. 
	case 'H':
		opts->hide = opt_add_string(opts->hide, arg);
		break;


	/*
	 key 가 / 'L'일 경우, arg 경로가 / libmcount 디렉토리인지 
	확인하고, 그렇다면 경고 메시지를 / 출력합니다. 이후에 / 
	이어지는 / OPT_loc_filter 케이스로 진행됩니다. 
	*/
	case 'L':
		if (is_libmcount_directory(arg))
			pr_warn("--libmcount-path option should be used to set libmcount path.\n");
	
	
		/* fall through */
	/*
	 key 가 / OPT_loc_filter 일 경우, arg 문자열에서 "@hide"를 / 
	찾습니다. 찾지 못하면 opts->loc_filter 에 / arg 문자열을 / 
	추가하고, 찾으면 문자열을 / 분할하고 앞부분에 / '!' 접두사를 
	/ 붙여 추가합니다. 위치 필터가 / 특정 위치에 / 집중되므로 
	스케줄 이벤트를 / 표시하는 / 것을 / 비활성화합니다. 
	*/
	case OPT_loc_filter:
		pos = strstr(arg, "@hide");
		if (!pos)
			opts->loc_filter = opt_add_string(opts->loc_filter, arg);
		else {
			*pos = '\0';
			opts->loc_filter = opt_add_prefix_string(opts->loc_filter, "!", arg);
		}
		/*
		 * location filter focuses onto a given location,
		 * displaying sched event with it is annoying.
		 */
		opts->no_sched = true;
		break;
	/*
	 key 가 / 'v'일 경우, debug 변수를 / 증가시킵니다. 이는 / 
	디버그 레벨을 / 증가시킵니다. 
	*/
	case 'v':
		debug++;
		break;

	/*
	 key 가 / 'd'일 경우, arg 문자열의 끝에 / 있는 / 슬래시를 / 
	제거하여 / opts->dirname 에 / 저장합니다. 
	*/
	case 'd':
		opts->dirname = remove_trailing_slash(arg);
		break;

	/*
	key 가 / 'b'일 경우, arg 문자열을 / 파싱하여 / opts->bufsize 에 / 
	저장합니다. bufsize 가 / 페이지 크기의 배수가 / 아니면 경고 
	메시지를 / 출력하고, ROUND_UP 매크로를 / 사용하여 / 페이지 
	크기의 배수로 만듭니다. 
	*/
	case 'b':
		opts->bufsize = parse_size(arg);
		if (opts->bufsize & (getpagesize() - 1)) {
			pr_use("buffer size should be multiple of page size\n");
			opts->bufsize = ROUND_UP(opts->bufsize, getpagesize());
		}
		break;

	/*
	 key 가 / 'k'일 경우, 커널 트레이싱을 / 활성화하고 커널 깊이를 
	/ 1 로 설정합니다. 
	*/
	case 'k':
		opts->kernel = true;
		opts->kernel_depth = 1;
		break;

	/*
	 key 가 / 'K'일 경우, 커널 트레이싱을 / 
	활성화하고 arg 문자열을 / 정수로 변환하여 / 커널 깊이를 / 
	설정합니다. 깊이가 / 1 보다 작거나 50 보다 크면 경고 메시지를 
	/ 출력하고 깊이를 / 1 로 설정합니다. 
	*/
	case 'K':
		opts->kernel = true;
		opts->kernel_depth = strtol(arg, NULL, 0);
		if (opts->kernel_depth < 1 || opts->kernel_depth > 50) {
			pr_use("invalid kernel depth: %s. Set depth to 1.\n", arg);
			opts->kernel_depth = 1;
		}
		break;

	/*
	 key 가 / 's'일 경우, opts->sort_keys 에 / arg 문자열을 / 
	추가합니다. 
	*/
	case 's':
		opts->sort_keys = opt_add_string(opts->sort_keys, arg);
		break;

	/*
	 key 가 / 'S'일 경우, arg 문자열을 / opts->script_file 에 / 
	저장합니다. 
	*/
	case 'S':
		opts->script_file = arg;
		break;

	/*
	 key 가 / 't'일 경우, 기본 옵션을 / 파싱 중이고 이미 시간 필터 
	또는 / 시간 범위가 / 설정되어 있으면 아무 작업도 하지 않습니다. 
	그렇지 않으면 default_opts 에 / 시간 필터를 / 	추가하고, arg 문자열을 / 파싱하여 / opts->threshold 에 / 
	저장합니다. 시간이 유효하지 않으면 경고 메시지를 / 출력하고 
	기본 최대값 바로 아래로 설정합니다. 시간이 범위가 / 설정되어 
	있으면 경고 메시지를 / 출력하고 범위를 / 초기화합니다. 
	*/
	case 't':
		/* do not override time-filter or time-range if it's already set */
		if (parsing_default_opts) {
			if (opts->threshold || opts->range.start || opts->range.stop)
				break;
		}

		/* add time-filter to uftrace.data/default.opts */
		strv_append(&default_opts, "-t");
		strv_append(&default_opts, arg);

		opts->threshold = parse_time(arg, 3);
		if (opts->threshold >= OPT_THRESHOLD_MAX) {
			pr_use("invalid time given: %lu (ignoring..)\n", opts->threshold);
			opts->threshold = OPT_THRESHOLD_MAX - 1;
		}
		if (opts->range.start || opts->range.stop) {
			pr_use("--time-range cannot be used with --time-filter\n");
			opts->range.start = opts->range.stop = 0;
		}
		break;

	/*
	 key 가 / 'A'일 경우, opts->args 에 / arg 문자열을 / 추가합니다. 
	*/
	case 'A':
		opts->args = opt_add_string(opts->args, arg);
		break;

	/*
	key 가 / 'R'일 경우, opts->retval 에 / arg 문자열을 / 
	추가합니다. 
	*/
	case 'R':
		opts->retval = opt_add_string(opts->retval, arg);
		break;

	//  key 가 / 'a'일 경우, opts->auto_args 를 / true 로 설정합니다. 
	case 'a':
		opts->auto_args = true;
		break;

	/*
	key 가 / 'l'일 경우, opts->force 를 / true 로 설정하고,
	 opts->nest_libcall 도 true 로 설정합니다. 
	 이는 / --nest-libcall 옵션이 --force 옵션을 / 암시한다는 / 의미입니다. 
	*/
	case 'l':
		/* --nest-libcall implies --force option */
		opts->force = true;
		opts->nest_libcall = true;
		break;

	/*
	key 가 / 'f'일 경우, arg 문자열을 / opts->fields 에 / 
	저장합니다. 
	*/
	case 'f':
		opts->fields = arg;
		break;

	/*
	 key 가 / 'r'일 경우, arg 문자열을 / 파싱하여 / opts->range 에 / 
	저장합니다. 파싱에 / 실패하면 경고 메시지를 / 
	출력합니다. opts->threshold 가 / 설정되어 있으면 경고 메시지를 / 
	출력하고 opts->threshold 를 / 0 으로 설정합니다. 
	*/
	case 'r':
		if (!parse_time_range(&opts->range, arg))
			pr_use("invalid time range: %s (ignoring...)\n", arg);
		if (opts->threshold) {
			pr_use("--time-filter cannot be used with --time-range\n");
			opts->threshold = 0;
		}
		break;


	//  key 가 / 'P'일 경우, opts->patch 에 / arg 문자열을 / 추가합니다. 
	case 'P':
		opts->patch = opt_add_string(opts->patch, arg);
		break;

	/*
	key 가 / 'U'일 경우, opts->patch 에 / arg 문자열 앞에 / '!' 
	접두사를 / 붙여 추가합니다. 
	*/
	case 'U':
		opts->patch = opt_add_prefix_string(opts->patch, "!", arg);
		break;

	/*
	key 가 / 'Z'일 경우, arg 문자열을 / 정수로 변환하여 
	/ opts->size_filter 에 / 저장합니다. 변환된 값이 0 이하이면 경고 
	메시지를 / 출력하고 opts->size_filter 를 / 0 으로 설정합니다. 
	*/
	case 'Z':
		opts->size_filter = strtol(arg, NULL, 0);
		if (opts->size_filter <= 0) {
			pr_use("--size-filter should be positive\n");
			opts->size_filter = 0;
		}
		break;

	/*
	 key 가 / 'E'일 경우, arg 가 / "list"와 일치하면 경고 메시지를 
	/ 출력하고 opts->list_event 를 / true 로 설정합니다. 그렇지 
	않으면 opts->event 에 / arg 문자열을 / 추가합니다. 
	*/
	case 'E':
		if (!strcmp(arg, "list")) {
			pr_use("'-E list' is deprecated, use --list-event instead.\n");
			opts->list_event = true;
		}
		else
			opts->event = opt_add_string(opts->event, arg);
		break;

	//  key 가 / 'W'일 경우, opts->watch 에 / arg 문자열을 / 추가합니다. 
	case 'W':
		opts->watch = opt_add_string(opts->watch, arg);
		break;

	//  key 가 / 'e'일 경우, opts->estimate_return 을 / true 로 설정합니다. 
	case 'e':
		opts->estimate_return = true;
		break;

	/*
	 key 가 / 'V'일 경우, uftrace_version 문자열을 / 출력하고 
	함수에서 -1 을 / 반환합니다. 
	*/
	case 'V':
		pr_out("%s\n", uftrace_version);
		return -1;


	//  key 가 / 'g'일 경우, opts->agent 를 / true 로 설정합니다. 
	case 'g':
		opts->agent = true;
		break;

	// key 가 / 'h'일 경우, 함수에서 -3 을 / 반환합니다. 
	case 'h':
		return -3;

	/*
	 key 가 / 'p'일 경우, arg 문자열을 / 정수로 변환하여 
	 / opts->pid 에 / 저장하고, opts->exename 을 / 빈 문자열로 설정합니다. 
	*/
	case 'p':
		opts->pid = strtol(arg, NULL, 0);
		opts->exename = "";
		break;



	/*
	 key 가 / OPT_libmcount_path 일 경우,
	 arg 문자열을 / opts->lib_path 에 / 저장합니다. 
	*/
	case OPT_libmcount_path:
		opts->lib_path = arg;
		break;


	// key 가 / OPT_usage 일 경우, 함수에서 -2 를 / 반환합니다. 
	case OPT_usage:
		return -2;


	//  key 가 / OPT_flat 일 경우, opts->flat 을 / true 로 설정합니다. 
	case OPT_flat:
		opts->flat = true;
		break;


	/*
	 key 가 / OPT_no_libcall 일 경우, opts->libcall 을 / false 로 
	설정합니다. 
	*/
	case OPT_no_libcall:
		opts->libcall = false;
		break;



	/*
	 key 가 / OPT_symbols 일 경우, opts->print_symtab 을 / true 로 
	설정합니다. 
	*/
	case OPT_symbols:
		opts->print_symtab = true;
		break;


	/*
	 key 가 / OPT_logfile 일 경우, arg 문자열을 / opts->logfile 에 / 
	저장합니다. 
	*/
	case OPT_logfile:
		opts->logfile = arg;
		break;


	// key 가 / OPT_force 일 경우, opts->force 를 / true 로 설정합니다. 
	case OPT_force:
		opts->force = true;
		break;


	//  key 가 / OPT_task 일 경우, opts->show_task 를 / true 로 설정합니다.
	case OPT_task:
		opts->show_task = true;
		break;


	/*
	 key 가 / OPT_tid_filter 일 경우, arg 문자열을 / 정수로 변환한 
	값이 0 이하이면 경고 메시지를 / 출력합니다. 그렇지 
	않으면 opts->tid 에 / arg 문자열을 / 추가합니다. 
	*/
	case OPT_tid_filter:
		if (strtol(arg, NULL, 0) <= 0)
			pr_use("invalid thread id: %s\n", arg);
		else
			opts->tid = opt_add_string(opts->tid, arg);
		break;


	/*
	key 가 / OPT_no_merge 일 경우, opts->no_merge 를 / true 로 
	설정합니다. 
	*/
	case OPT_no_merge:
		opts->no_merge = true;
		break;


	//  key 가 / OPT_nop 일 경우, opts->nop 을 / true 로 설정합니다. 
	case OPT_nop:
		opts->nop = true;
		break;


	//  key 가 / OPT_time 일 경우, opts->time 을 / true 로 설정합니다. 
	case OPT_time:
		opts->time = true;
		break;





	/*
	 key 가 / OPT_max_stack 일 경우, arg 문자열을 / 정수로 변환하여 / 
	opts->max_stack 에 / 저장합니다. 변환된 값이 
	0 이하이거나 OPT_RSTACK_MAX 보다 크면 경고 메시지를 / 출력하고 
	기본 스택 깊이로 설정합니다. 
	*/
	case OPT_max_stack:
		opts->max_stack = strtol(arg, NULL, 0);
		if (opts->max_stack <= 0 || opts->max_stack > OPT_RSTACK_MAX) {
			pr_use("max stack depth should be >0 and <%d\n", OPT_RSTACK_MAX);
			opts->max_stack = OPT_RSTACK_DEFAULT;
		}
		break;


	/*
	 key 가 / OPT_host 일 경우, arg 문자열을 / opts->host 에 / 
	저장합니다. 
	*/
	case OPT_host:
		opts->host = arg;
		break;


	/*
	 key 가 / OPT_port 일 경우, arg 문자열을 / 정수로 변환하여 / 
	opts->port 에 / 저장합니다. 변환된 값이 0 이하이면 경고 
	메시지를 / 출력하고 기본 포트 번호로 설정합니다. 
	*/
	case OPT_port:
		opts->port = strtol(arg, NULL, 0);
		if (opts->port <= 0) {
			pr_use("invalid port number: %s (ignoring..)\n", arg);
			opts->port = UFTRACE_RECV_PORT;
		}
		break;


	/*
	key 가 / OPT_nopager 일 경우, opts->use_pager 를 / false 로 
	설정합니다. 
	*/
	case OPT_nopager:
		opts->use_pager = false;
		break;



	/*
	 key 가 / OPT_avg_total 일 경우, opts->avg_total 을 / true 로 
	설정합니다. 
	*/
	case OPT_avg_total:
		opts->avg_total = true;
		break;



	/*
	key 가 / OPT_avg_self 일 경우, opts->avg_self 를 / true 로 
	설정합니다. 
	*/
	case OPT_avg_self:
		opts->avg_self = true;
		break;



	/*
	 key 가 / OPT_color 일 경우, parse_color 함수를 / 사용하여 / 
	arg 문자열을 / 파싱하고 opts->color 에 / 저장합니다. 만약 
	색상이 COLOR_UNKNOWN 이면 경고 메시지를 / 출력하고 opts->color 를 / 
	COLOR_AUTO 로 설정합니다. 
	*/
	case OPT_color:
		opts->color = parse_color(arg);
		if (opts->color == COLOR_UNKNOWN) {
			pr_use("unknown color setting: %s (ignoring..)\n", arg);
			opts->color = COLOR_AUTO;
		}
		break;


	/*
	 key 가 / OPT_disabled 일 경우, 경고 메시지를 / 출력하고 
	 opts->trace 를 / TRACE_STATE_OFF 로 설정합니다. 
	*/
	case OPT_disabled:
		pr_use("'--disable' is deprecated, use --trace=off instead.\n");
		opts->trace = TRACE_STATE_OFF;
		break;




	/*
	 key 가 / OPT_trace 일 경우, arg 문자열이 "on"이면 opts->trace 를 / 
	TRACE_STATE_ON 으로 설정하고, / "off"이면 TRACE_STATE_OFF 로 
	설정합니다. 그 외의 값이면 경고 메시지를 / 출력합니다. 
	*/
	case OPT_trace:
		if (!strcmp(arg, "on"))
			opts->trace = TRACE_STATE_ON;
		else if (!strcmp(arg, "off"))
			opts->trace = TRACE_STATE_OFF;
		else
			pr_use("unknown tracing state: %s (ignoring..)\n", arg);
		break;



	/*
	key 가 / OPT_demangle 일 경우, parse_demangle 함수를 / 사용하여 / 
	arg 문자열을 / 파싱하고 demangler 에 / 저장합니다. 
	만약 demangler 가 / DEMANGLE_ERROR 이면 경고 메시지를 / 
	출력하고 DEMANGLE_SIMPLE 로 설정합니다. 
	만약 DEMANGLE_NOT_SUPPORTED 이면 지원하지 않는다는 / 메시지를 / 
	출력하고 DEMANGLE_SIMPLE 로 설정합니다. 
	*/
	case OPT_demangle:
		demangler = parse_demangle(arg);
		if (demangler == DEMANGLE_ERROR) {
			pr_use("unknown demangle value: %s (ignoring..)\n", arg);
			demangler = DEMANGLE_SIMPLE;
		}
		else if (demangler == DEMANGLE_NOT_SUPPORTED) {
			pr_use("'%s' demangler is not supported\n", arg);
			demangler = DEMANGLE_SIMPLE;
		}
		break;


	/*
	 key 가 / OPT_dbg_domain 일 경우, 
	 arse_debug_domain 함수를 / 호출하여 
	/ arg 문자열을 / 파싱합니다. 
	*/
	case OPT_dbg_domain:
		parse_debug_domain(arg);
		break;


	//  key 가 / OPT_report 일 경우, opts->report 를 / true 로 설정합니다. 
	case OPT_report:
		opts->report = true;
		break;



	/*
	 key 가 / OPT_column_view 일 경우, opts->column_view 를 / true 로 
	설정합니다. 
	*/
	case OPT_column_view:
		opts->column_view = true;
		break;



	/*
	 key 가 / OPT_column_offset 일 경우, arg 문자열을 / 정수로 변환하여 
	/ opts->column_offset 에 / 저장합니다. 만약 변환된 값이 0 보다 
	작으면 기본 값 OPT_COLUMN_OFFSET 로 설정합니다. 
	*/
	case OPT_column_offset:
		opts->column_offset = strtol(arg, NULL, 0);
		if (opts->column_offset < 0)
			opts->column_offset = OPT_COLUMN_OFFSET;
		break;




	/*
	 key 가 / OPT_bind_not 일 경우, opts->want_bind_not 을 / true 로 
	설정합니다. 
	*/
	case OPT_bind_not:
		opts->want_bind_not = true;
		break;


	/*
	 key 가 / OPT_task_newline 일 경우, opts->task_newline 을 
	 / true 로 설정합니다. 
	*/
	case OPT_task_newline:
		opts->task_newline = true;
		break;



	/*
	 key 가 / OPT_chrome_trace 일 경우,
	  opts->chrome_trace 를 / true 로 설정합니다. 
	*/
	case OPT_chrome_trace:
		opts->chrome_trace = true;
		break;



	/*
	 key 가 / OPT_flame_graph 일 경우, 
	 opts->flame_graph 를 / true 로 설정합니다. 
	*/
	case OPT_flame_graph:
		opts->flame_graph = true;
		break;




	/*
	 key 가 / OPT_graphviz 일 경우, 
	 opts->graphviz 를 / true 로 설정합니다. 
	*/
	case OPT_graphviz:
		opts->graphviz = true;
		break;



	/*
	 key 가 / OPT_diff 일 경우, 
	 arg 문자열을 / opts->diff 에 / 저장합니다. 
	*/
	case OPT_diff:
		opts->diff = arg;
		break;


	/*
	 key 가 / OPT_diff_policy 일 경우, 
	 arg 문자열을 / opts->diff_policy 에 / 저장합니다. 
	*/
	case OPT_diff_policy:
		opts->diff_policy = arg;
		break;



	/*
	key 가 / OPT_format 일 경우, arg 문자열이 
	"normal"이면 format_mode 를 / FORMAT_NORMAL 로 설정하고, 
	"html"이면 FORMAT_HTML 로 설정합니다. "html"인 경우 opts->color 가 
	/ COLOR_AUTO 이면 COLOR_ON 으로 설정합니다. 다른 값이면 경고 
	메시지를 / 출력하고 format_mode 를 / FORMAT_NORMAL 로 설정합니다. 
	*/
	case OPT_format:
		if (!strcmp(arg, "normal"))
			format_mode = FORMAT_NORMAL;
		else if (!strcmp(arg, "html")) {
			format_mode = FORMAT_HTML;
			if (opts->color == COLOR_AUTO)
				opts->color = COLOR_ON;
		}
		else {
			pr_use("invalid format argument: %s\n", arg);
			format_mode = FORMAT_NORMAL;
		}
		break;



	/*
	 key 가 / OPT_sort_column 일 경우, arg 문자열을 / 정수로 변환하여 
	/ opts->sort_column 에 / 저장합니다. 변환된 값이 0 보다 
	작거나 OPT_SORT_COLUMN 보다 크면 경고 메시지를 / 출력하고
	 opts->sort_column 을 / OPT_SORT_COLUMN 으로 설정합니다. 
	*/
	case OPT_sort_column:
		opts->sort_column = strtol(arg, NULL, 0);
		if (opts->sort_column < 0 || opts->sort_column > OPT_SORT_COLUMN) {
			pr_use("invalid column number: %d\n", opts->sort_column);
			pr_use("force to set it to --sort-column=%d for diff percentage\n",
			       OPT_SORT_COLUMN);
			opts->sort_column = OPT_SORT_COLUMN;
		}
		break;




	/*
	 key 가 / OPT_num_thread 일 경우, arg 문자열을 / 정수로 변환하여 / 
	opts->nr_thread 에 / 저장합니다. 변환된 값이 0 보다 작으면 경고 
	메시지를 / 출력하고 opts->nr_thread 를 / 0 으로 설정합니다. 
	*/
	case OPT_num_thread:
		opts->nr_thread = strtol(arg, NULL, 0);
		if (opts->nr_thread < 0) {
			pr_use("invalid thread number: %s\n", arg);
			opts->nr_thread = 0;
		}
		break;



	/*
	 key 가 / OPT_no_comment 일 경우, 
	 opts->comment 를 / false 로 설정합니다. 
	*/
	case OPT_no_comment:
		opts->comment = false;
		break;


	/*
	 key 가 / OPT_libmcount_single 일 경우, 
	 opts->libmcount_single 을 / true 로 설정합니다. 
	*/
	case OPT_libmcount_single:
		opts->libmcount_single = true;
		break;




	/*
	key 가 / OPT_rt_prio 일 경우, arg 문자열을 / 정수로 변환하여 / 
	opts->rt_prio 에 / 저장합니다. 변환된 값이 1 보다 작거나 
	99 보다 크면 경고 메시지를 / 출력하고 opts->rt_prio 를 / 0 으로 
	설정합니다. 
	*/
	case OPT_rt_prio:
		opts->rt_prio = strtol(arg, NULL, 0);
		if (opts->rt_prio < 1 || opts->rt_prio > 99) {
			pr_use("invalid rt prioity: %d (ignoring...)\n", opts->rt_prio);
			opts->rt_prio = 0;
		}
		break;


	/*
	 key 가 / OPT_kernel_bufsize 일 경우, parse_size 함수를 / 사용하여 / 
	arg 문자열을 / 파싱하고 opts->kernel_bufsize 에 / 
	저장합니다. kernel_bufsize 가 / 페이지 크기의 배수가 / 아니면 
	경고 메시지를 / 출력하고 ROUND_UP 매크로를 / 사용하여 / 페이지 
	크기의 배수로 만듭니다. 
	*/
	case OPT_kernel_bufsize:
		opts->kernel_bufsize = parse_size(arg);
		if (opts->kernel_bufsize & (getpagesize() - 1)) {
			pr_use("buffer size should be multiple of page size\n");
			opts->kernel_bufsize = ROUND_UP(opts->kernel_bufsize, getpagesize());
		}
		break;



	/*
	key 가 / OPT_kernel_skip_out 일 경우, 
	opts->kernel_skip_out 을 / true 로 설정합니다. 
	이는 / 더 이상 사용되지 않는 / 옵션입니다. 
	*/
	case OPT_kernel_skip_out: /* deprecated */
		opts->kernel_skip_out = true;
		break;



	/*
	 key 가 / OPT_kernel_full 일 경우, 
	 opts->kernel_skip_out 을 / false 로 설정합니다.
	  setup_kernel_tracing() 함수도 참조해야 합니다.
	*/
	case OPT_kernel_full:
		opts->kernel_skip_out = false;
		/* see setup_kernel_tracing() also */
		break;



	/*
	key 가 / OPT_kernel_only 일 경우, 
	opts->kernel_only 를 / true 로 설정합니다. 
	*/
	case OPT_kernel_only:
		opts->kernel_only = true;
		break;




	/*
	 key 가 / OPT_sample_time 일 경우, 
	 arg 문자열을 / 파싱하여 / opts->sample_time 에 / 저장합니다. 
	 parse_time 함수는 / arg 문자열을 / 시간으로 변환합니다. 
	*/
	case OPT_sample_time:
		opts->sample_time = parse_time(arg, 9);
		break;




	/*
	key 가 / OPT_list_event 일 경우,
	 opts->list_event 를 / true 로 설정합니다. 
	*/
	case OPT_list_event:
		opts->list_event = true;
		break;




	/*
	key 가 / OPT_run_cmd 일 경우, opts->run_cmd 가 / 이미 설정되어 
	있으면 경고 메시지를 / 출력하고 free_parsed_cmdline 함수를 / 
	호출하여 / 기존 명령을 / 해제합니다. 그런 
	다음 parse_cmdline 함수를 / 사용하여 / arg 문자열을 / 
	파싱하고 opts->run_cmd 에 / 저장합니다. 
	*/
	case OPT_run_cmd:
		if (opts->run_cmd) {
			pr_warn("intermediate --run-cmd argument is ignored.\n");
			free_parsed_cmdline(opts->run_cmd);
		}
		opts->run_cmd = parse_cmdline(arg, NULL);
		break;



	/*
	key 가 / OPT_opt_file 일 경우, 
	arg 문자열을 / opts->opt_file 에 / 저장합니다. 
	*/
	case OPT_opt_file:
		opts->opt_file = arg;
		break;


	/*
	key 가 / OPT_keep_pid 일 경우,
	 opts->keep_pid 를 / true 로 설정합니다. 
	*/
	case OPT_keep_pid:
		opts->keep_pid = true;
		break;



	/*
	 key 가 / OPT_event_full 일 경우, 
	 opts->event_skip_out 을 / false 로 설정합니다. 
	*/
	case OPT_event_full:
		opts->event_skip_out = false;
		break;


	//  key 가 / OPT_record 일 경우, opts->record 를 / true 로 설정합니다. 
	case OPT_record:
		opts->record = true;
		break;


	/*
	key 가 / OPT_no_args 일 경우, 
	opts->show_args 를 / false 로 설정합니다. 
	*/
	case OPT_no_args:
		opts->show_args = false;
		break;



	//  key 가 / OPT_libname 일 경우, opts->libname 을 / true 로 설정합니다. 
	case OPT_libname:
		opts->libname = true;
		break;





	/*
	 key 가 / OPT_match_type 일 경우, parse_filter_pattern 함수를 / 
	사용하여 / arg 문자열을 / 파싱하고 opts->patt_type 에 / 
	저장합니다. 만약 opts->patt_type 이 PATT_NONE 이면 경고 메시지를 / 
	출력하고 PATT_REGEX 로 설정합니다. 
	*/
	case OPT_match_type:
		opts->patt_type = parse_filter_pattern(arg);
		if (opts->patt_type == PATT_NONE) {
			pr_use("invalid match pattern: %s (ignoring...)\n", arg);
			opts->patt_type = PATT_REGEX;
		}
		break;


	/*
	 key 가 / OPT_no_randomize_addr 일 경우, 
	 opts->no_randomize_addr 를 / true 로 설정합니다. 
	*/
	case OPT_no_randomize_addr:
		opts->no_randomize_addr = true;
		break;


	/*
	 key 가 / OPT_no_event 일 경우, 
	 opts->no_event 를 / true 로 설정합니다. 
	*/
	case OPT_no_event:
		opts->no_event = true;
		break;



	/*
	 key 가 / OPT_no_sched 일 경우,
	  opts->no_sched 를 / true 로 설정합니다. 
	*/
	case OPT_no_sched:
		opts->no_sched = true;
		break;



	/*
	key 가 / OPT_no_sched_preempt 일 경우,
	 opts->no_sched_preempt 를 / true 로 설정합니다. 
	*/
	case OPT_no_sched_preempt:
		opts->no_sched_preempt = true;
		break;



	/*
	 key 가 / OPT_signal 일 경우,
	  opts->sig_trigger 에 / arg 문자열을 / 추가합니다. 
	*/
	case OPT_signal:
		opts->sig_trigger = opt_add_string(opts->sig_trigger, arg);
		break;


	// key 가 / OPT_srcline 일 경우, opts->srcline 을 / true 로 설정합니다. 
	case OPT_srcline:
		opts->srcline = true;
		break;



	/*
	 key 가 / OPT_with_syms 일 경우, 
	 arg 문자열을 / opts->with_syms 에 / 저장합니다. 
	*/
	case OPT_with_syms:
		opts->with_syms = arg;
		break;



	/*
	 key 가 / OPT_clock 일 경우, arg 문자열이 "mono", "mono_raw", 
	"boot" 중 하나와 일치하지 않으면 경고 메시지를 / 
	출력하고 arg 를 / "mono"로 설정합니다. 그런 다음 arg 를 /
	 opts->clock 에 / 저장합니다. 
	*/
	case OPT_clock:
		if (strcmp(arg, "mono") && strcmp(arg, "mono_raw") && strcmp(arg, "boot")) {
			pr_use("invalid clock source: '%s' "
			       "(force to use 'mono')\n",
			       arg);
			arg = "mono";
		}
		opts->clock = arg;
		break;


	//  key 가 / OPT_mermaid 일 경우, opts->mermaid 를 / true 로 설정합니다.
	case OPT_mermaid:
		opts->mermaid = true;
		break;


	/*
	 key 가 / 위의 모든 경우에 / 해당하지 않으면 
	 함수에서 -1 을 / 	반환합니다. 
	*/
	default:
		return -1;
	}


	// 함수가 / 성공적으로 완료되면 0 을 / 반환합니다. 
	return 0;
}



/*
update_subcmd 라는 / 정적 함수를 / 정의합니다. 
이 함수는 / 명령어 문자열 cmd 에 / 따라
 uftrace_opts 구조체의 mode 필드를 / 설정합니다. 
*/
static void update_subcmd(struct uftrace_opts *opts, char *cmd)
{

	/*
	 cmd 가 / "record"와 같으면, 
	 opts->mode 를 / UFTRACE_MODE_RECORD 로 설정합니다. 
	*/
	if (!strcmp(cmd, "record"))
		opts->mode = UFTRACE_MODE_RECORD;



	/*
	 cmd 가 / "replay"와 같으면, 
	 opts->mode 를 / UFTRACE_MODE_REPLAY 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "replay"))
		opts->mode = UFTRACE_MODE_REPLAY;


	/*
	 cmd 가 / "report"와 같으면, 
	 opts->mode 를 / UFTRACE_MODE_REPORT 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "report"))
		opts->mode = UFTRACE_MODE_REPORT;



	/*
	cmd 가 / "live"와 같으면,
	 opts->mode 를 / UFTRACE_MODE_LIVE 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "live"))
		opts->mode = UFTRACE_MODE_LIVE;



	/*
	 cmd 가 / "graph"와 같으면, 
	 opts->mode 를 / UFTRACE_MODE_GRAPH 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "graph"))
		opts->mode = UFTRACE_MODE_GRAPH;


	/*
	 cmd 가 / "info"와 같으면,
	  opts->mode 를 / UFTRACE_MODE_INFO 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "info"))
		opts->mode = UFTRACE_MODE_INFO;


	/*
	 cmd 가 / "dump"와 같으면,
	 opts->mode 를 / UFTRACE_MODE_DUMP 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "dump"))
		opts->mode = UFTRACE_MODE_DUMP;


	/*
	 cmd 가 / "recv"와 같으면, 
	 opts->mode 를 / UFTRACE_MODE_RECV 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "recv"))
		opts->mode = UFTRACE_MODE_RECV;


	/*
	 cmd 가 / "script"와 같으면, 
	 opts->mode 를 / UFTRACE_MODE_SCRIPT 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "script"))
		opts->mode = UFTRACE_MODE_SCRIPT;


	/*
	 cmd 가 / "tui"와 같으면,
	  opts->mode 를 / UFTRACE_MODE_TUI 로 설정합니다. 
	*/
	else if (!strcmp(cmd, "tui"))
		opts->mode = UFTRACE_MODE_TUI;


	/*
	cmd 가 / 위의 모든 경우에 / 해당하지 않으면,
	 opts->mode 를 / UFTRACE_MODE_INVALID 로 설정합니다. 
	*/
	else
		opts->mode = UFTRACE_MODE_INVALID;
}





/*
parse_opt_file 라는 / 정적 함수를 / 정의합니다.
 이 함수는 / 옵션 파일을 / 파싱하여 / 명령줄 인자로 추가합니다. 
인자로 argc(인자 개수), argv(인자 배열), filename(옵션 파일 
이름), opts(옵션 구조체)를 / 받습니다. 

*/
static void parse_opt_file(int *argc, char ***argv, char *filename, struct uftrace_opts *opts)
{

	/*
	여러 변수를 / 선언합니다. file_argc 와 file_argv 는 / 옵션 파일의 
	인자 개수와 인자 배열을 / 저장합니다.
 	buf 는 / 파일 내용을 / 저장할 버퍼입니다. 
 	stbuf 는 / 파일 정보를 / 저장할 구조체입니다. 
 	fp 는 / 파일 포인터입니다. 
 	orig_exename 은 / opts 의 exename 을 / 저장합니다.
  	has_subcmd 는 / 서브 명령어 존재 여부를 / 나타내는 / 플래그입니다. 
	*/
	int file_argc;
	char **file_argv;
	char *buf;
	struct stat stbuf;
	FILE *fp;
	char *orig_exename = opts->exename;
	bool has_subcmd = false;



	/*
	stat 함수를 / 사용하여 / filename 의 파일 정보를 / 가져옵니다. 
	실패하면 경고 메시지를 / 출력하고 프로그램을 / 종료합니다. 
	*/
	if (stat(filename, &stbuf) < 0) {
		pr_use("Cannot use opt-file: %s: %m\n", filename);
		exit(0);
	}


	/*
	getopt_long 함수가 / argv[0]을 / 처리할 수 있도록 더미 문자열 
	"uftrace "를 / 추가하기 위해 buf 를 / 할당하고 문자열을 / 
	복사합니다. 
	*/
	/* prepend dummy string since getopt_long cannot process argv[0] */
	buf = xmalloc(stbuf.st_size + 9);
	strncpy(buf, "uftrace ", 9);



	/*
	 fopen 함수를 / 사용하여 / filename 을 / 읽기 모드로 엽니다. 
	실패하면 오류 메시지를 / 출력합니다. fread_all 함수를 / 
	사용하여 / 파일 내용을 / buf + 8 에 / 읽어옵니다. 파일을 / 
	닫고 버퍼의 끝에 / 널 문자를 / 추가합니다. 
	*/
	fp = fopen(filename, "r");
	if (fp == NULL)
		pr_err("Open failed: %s", filename);
	fread_all(buf + 8, stbuf.st_size, fp);
	fclose(fp);
	buf[stbuf.st_size + 8] = '\0';



	/*
	parse_cmdline 함수를 / 사용하여 / buf 를 / 파싱하여 / 
	file_argc 와 file_argv 를 / 설정합니다. 
	*/
	file_argv = parse_cmdline(buf, &file_argc);


	//  오류 보고를 / 위해 opts->opt_file 을 / 초기화합니다. 
	/* clear opt_file for error reporting */
	opts->opt_file = NULL;


	//  다른 라운드를 / 시작하기 위해 getopt 를 / 다시 초기화합니다. 
	/* re-initialize getopt as we start another round */
	optind = 0;



	/*
	file_argv[1]의 첫 번째 문자가 / '-'가 / 아니면 opts->mode 의 값을 
	/ orig_mode 에 / 저장합니다. 이는 / 옵션 파일의 첫 번째 인자가 
	/ 명령어일 가능성을 / 확인하는 / 것입니다. 
	*/
	if (file_argv[1][0] != '-') {
		int orig_mode = opts->mode;


		/*
		file_argv[1]을 / 명령어로 해석하고 
		update_subcmd 함수를 / 호출하여 / opts->mode 를 / 설정합니다. 
		*/
		update_subcmd(opts, file_argv[1]);


		/*
		 만약 opts->mode 가 / 유효하지 않으면,
		  opts->mode 를 / 원래 모드로 되돌리고 
		has_subcmd 를 / true 로 설정합니다. 
		*/
		if (opts->mode == UFTRACE_MODE_INVALID) {
			opts->mode = orig_mode;
			has_subcmd = true;
		}



		/*
		 그렇지 않으면 원래 모드가 / 유효하고 opts->mode 와 다르면 경고 
		메시지를 / 출력하고 opts->mode 를 / 원래 모드로 되돌립니다. 
		그렇지 않으면 has_subcmd 를 / true 로 설정합니다. 
		*/
		else {
			if (orig_mode != UFTRACE_MODE_INVALID && orig_mode != opts->mode) {
				pr_use("ignore uftrace command in opt-file\n");
				opts->mode = orig_mode;
			}
			else {
				has_subcmd = true;
			}
		}
	}



	// 무한 루프를 / 시작하고, key 와 tmp 변수를 / 선언합니다. 
	while (true) {
		int key, tmp = 0;



		/*
		 getopt_long 함수를 / 사용하여 / 옵션을 / 파싱합니다. 
		 key 가 / -1 또는 / '?'이면 루프를 / 종료합니다. 
		 has_subcmd 가 / true 이고 
		 optind 가 / 1 이면 optind 를 / 증가시키고, 
		 그렇지 않으면 루프를 / 종료합니다. 
		*/
		key = getopt_long(file_argc, file_argv, uftrace_shopts, uftrace_options, &tmp);
		if (key == -1 || key == '?') {
			if (has_subcmd && optind == 1)
				optind++;
			else
				break;
		}


		/*
		 parse_option 함수를 / 호출하여 / 
		 현재 옵션을 / 파싱하고 opts 에 / 설정합니다. 
		*/
		parse_option(opts, key, optarg);
	}





	/*
	명령줄에서 exename 이 주어지지 않았고,
	 optind 가 / file_argc 보다 작으면 
	 argc 와 argv 를 / 파일에서 읽은 / 인자 개수와 인자 배열로 덮어씁니다. 
	*/
	/* overwrite argv only if it's not given on command line */
	if (orig_exename == NULL && optind < file_argc) {
		*argc = file_argc;
		*argv = file_argv;


		/*
		opts 구조체의 idx 를 / optind 로 설정하고, 
		exename 을 / file_argv[optind]로 설정합니다. 
		*/
		opts->idx = optind;
		opts->exename = file_argv[optind];




		/*
		 옵션 파일을 / 나중에 / 해제할 수 있도록 
		 opts->opt_file 에 / filename 을 / 설정합니다. 
		*/
		/* mark it to free at the end */
		opts->opt_file = filename;
	}


	/*
	 그렇지 않으면 exename 을 / 원래 값으로 되돌리고, 
	 free_parsed_cmdline 함수를 / 호출하여 / file_argv 에 / 
	할당된 메모리를 / 해제합니다. 
	*/
	else {
		opts->exename = orig_exename;
		free_parsed_cmdline(file_argv);
	}


	//  buf 에 / 할당된 메모리를 / 해제합니다. 
	free(buf);
}



/*
parse_script_opt 라는 / 함수를 / 정의합니다. 
이 함수는 / uftrace_opts 구조체를 / 인자로 받아
 스크립트 파일에서 옵션을 / 파싱합니다. 
*/
/*
 * Parse options in a script file header.  For example,
 *
 *   # uftrace-option: -F main -A malloc@arg1
 *   def uftrace_entry():
 *     pass
 *   ...
 *
 * Note that it only handles some options like filter, trigger,
 * argument, return values and maybe some more.
 */
void parse_script_opt(struct uftrace_opts *opts)
{

	/*
	 여러 변수를 / 선언합니다. 
	 fp 는 / 파일 포인터, 
	 opt_argc 는 / 옵션 인자의 개수, 
	opt_argv 는 / 옵션 인자의 배열, 
	line 은 / 파일에서 읽은 / 한 줄, 
	len 은 / 줄 길이, 
	optname 은 / 옵션 이름 문자열, 
	script_type 은 / 스크립트 유형, 
	comments 는 / 각 스크립트 유형의 주석 기호 배열
	comment 는 / 현재 스크립트 유형의 주석 기호, 
	comment_len 은 / 주석 기호의 길이입니다. 
	*/
	FILE *fp;
	int opt_argc;
	char **opt_argv;
	char *line = NULL;
	size_t len = 0;
	static const char optname[] = "uftrace-option";
	enum script_type_t script_type;
	const char *comments[SCRIPT_TYPE_COUNT] = { "", "#", "--" };
	const char *comment;
	size_t comment_len;


	//  opts->script_file 이 NULL 이면 함수를 / 종료합니다. 
	if (opts->script_file == NULL)
		return;




	/*
	fopen 함수를 / 사용하여 / opts->script_file 을 / 읽기 모드로 
	엽니다. 실패하면 오류 메시지를 / 출력합니다. 
	*/
	fp = fopen(opts->script_file, "r");
	if (fp == NULL)
		pr_err("cannot open script file: %s", opts->script_file);



	/*
	 get_script_type 함수를 / 호출하여 / 스크립트 파일의 유형을 / 
	결정합니다. 
	*/
	script_type = get_script_type(opts->script_file);




	/*
	 script_type 이 SCRIPT_UNKNOWN 이면 파일을 / 닫고
	  오류 메시지를 /출력합니다. 
	*/
	if (script_type == SCRIPT_UNKNOWN) {
		fclose(fp);
		pr_err("unknown script type");
	}


	/*
	현재 스크립트 유형의 주석 기호를 / comment 에 / 저장하고, 
	주석 기호의 길이를 / comment_len 에 / 저장합니다.
	*/
	comment = comments[script_type];
	comment_len = strlen(comment);



	/*
	 파일 fp 에서 한 줄씩 읽어옵니다. 
	 읽어온 줄은 / line 에 / 저장되고,
	  줄의 길이는 / len 에 / 저장됩니다. 
	  pos 라는 / 문자열 포인터 변수를 / 선언합니다. 
	*/
	while (getline(&line, &len, fp) > 0) {
		char *pos;



		/*
		읽어온 줄의 처음 comment_len 글자가 / comment 와 일치하지 않으면 
		다음 줄로 넘어갑니다. 
		*/
		if (strncmp(line, comment, comment_len))
			continue;




		/*
		 pos 를 / 주석 기호 다음으로 이동시키고, 
		 공백 문자를 / 건너뜁니다. 
		*/
		pos = line + comment_len;
		while (isspace(*pos))
			pos++;


		/*
		 pos 가 / optname("uftrace-option")과 일치하지 않으면 
		 다음 줄로 넘어갑니다. 
		*/
		if (strncmp(pos, optname, strlen(optname)))
			continue;




		/*
		 line 에서 ':' 문자를 / 찾아 pos 에 / 저장합니다. 
		 ':' 문자가 / 없으면 루프를 / 종료합니다. 
		*/
		/* extract option value */
		pos = strchr(line, ':');
		if (pos == NULL)
			break;





		/*
		디버그 메시지를 / 출력하여 
		/ 스크립트에서 옵션을 / 추가하고 
		있음을 / 알립니다. 
		*/
		pr_dbg("adding record option from script: %s", pos + 1);




		/*
		pos 에서 명령줄을 / 파싱하여 / opt_argc 와 opt_argv 를 / 
		설정합니다. 
		*/
		/* include ':' so that it can start with optind 1 */
		opt_argv = parse_cmdline(pos, &opt_argc);


		// getopt 를 / 다시 초기화합니다. 
		/* re-initialize getopt as we start another round */
		optind = 0;



		/*
		 무한 루프를 / 시작하고, getopt_long 함수를 / 사용하여 / 옵션을 
		 파싱합니다. key 가 / -1 또는 / '?'이면 루프를 / 종료합니다. 
		그렇지 않으면 parse_option 함수를 / 호출하여 / 현재 옵션을 / 
		opts 에 / 설정합니다. 
		*/
		while (true) {
			int key, tmp = 0;

			key = getopt_long(opt_argc, opt_argv, uftrace_shopts, uftrace_options,
					  &tmp);
			if (key == -1 || key == '?')
				break;

			parse_option(opts, key, optarg);
		}



		//  opt_argv 에 / 할당된 메모리를 / 해제하고 루프를 / 종료합니다. 
		free_parsed_cmdline(opt_argv);
		break;
	}



	// line 에 / 할당된 메모리를 / 해제하고, 파일을 / 닫습니다. 
	free(line);
	fclose(fp);
}


/*
uftrace_opts 구조체의 모든 동적 할당된 메모리를 / 해제하는 / 
함수입니다. 각 필드에 / 대해 free 함수를 / 호출하여 / 
메모리를 / 해제합니다. opts->run_cmd 는 / free_parsed_cmdline 함수를 
/ 사용하여 / 해제합니다. 
*/
static void free_opts(struct uftrace_opts *opts)
{
	free(opts->filter);
	free(opts->trigger);
	free(opts->sig_trigger);
	free(opts->sort_keys);
	free(opts->args);
	free(opts->retval);
	free(opts->tid);
	free(opts->event);
	free(opts->patch);
	free(opts->caller);
	free(opts->watch);
	free(opts->hide);
	free(opts->loc_filter);
	free_parsed_cmdline(opts->run_cmd);
}



/*
 parse_options 함수는 / 명령줄 옵션을 / 파싱하여 / 
uftrace_opts 구조체에 / 설정합니다. 먼저 optind 를 / 1 로 
초기화하여 / 옵션 파싱 인덱스를 / 설정합니다. 
*/
static int parse_options(int argc, char **argv, struct uftrace_opts *opts)
{
	/* initial option parsing index */
	optind = 1;


	// 무한 루프를 / 시작하고, key 와 tmp 변수를 / 선언합니다. 
	while (true) {
		int key, tmp = 0;



		/*
		 getopt_long 함수를 / 사용하여 / 옵션을 / 파싱합니다. key 가 
		 / -1 또는 / '?'이면 옵션 파싱을 / 종료할지 확인합니다.
		  optind 가 / argc 보다 작고 opts->mode 가 / 
		UFTRACE_MODE_INVALID 이면 argv[optind]를 / 명령어로 
		해석하고 update_subcmd 함수를 / 호출하여 / opts->mode 를 / 
		설정합니다. 
		*/
		key = getopt_long(argc, argv, uftrace_shopts, uftrace_options, &tmp);
		if (key == -1 || key == '?') {
			if (optind < argc && opts->mode == UFTRACE_MODE_INVALID) {
				update_subcmd(opts, argv[optind]);


				/*
				 만약 opts->mode 가 / 유효하면 optind 를 / 증가시키고 
				 루프의 처음으로 돌아갑니다. 그렇지 않으면 루프를 / 종료합니다. 
				*/
				if (opts->mode != UFTRACE_MODE_INVALID) {
					optind++;
					continue;
				}
			}
			break;
		}



		/*
		 parse_option 함수를 / 호출하여 / 현재 옵션을 / 파싱하고 
		 opts 에 / 설정합니다. 만약 tmp 가 / 0 보다 작으면 함수를 / 종료하고 
		오류 코드를 / 반환합니다. 
		*/
		tmp = parse_option(opts, key, optarg);
		if (tmp < 0)
			return tmp;
	}



	/*
	 루프가 / 종료된 후, optind 가 / argc 보다 작으면 opts->idx 를 / 
	optind 로 설정하고 opts->exename 을 / argv[optind]로 설정합니다. 
	함수가 / 성공적으로 완료되면 0 을 / 반환합니다. 
	*/
	if (optind < argc) {
		opts->idx = optind;
		opts->exename = argv[optind];
	}

	return 0;
}



/*
 apply_default_opts 라는 / 정적 함수를 / 정의합니다. 이 함수는 / 
기본 옵션 파일을 / 적용합니다. argc(인자 개수), argv(인자 
배열), opts(옵션 구조체)를 / 인자로 받습니다. basename 은 / 
기본 옵션 파일의 이름을 / 저장하고, opts_file 은 / 옵션 파일 
경로를 / 저장하며, stbuf 는 / 파일 정보를 / 저장합니다. 
*/
__used static void apply_default_opts(int *argc, char ***argv, struct uftrace_opts *opts)
{
	char *basename = "default.opts";
	char opts_file[PATH_MAX];
	struct stat stbuf;





	/*
	 opts->mode 가 / UFTRACE_MODE_RECORD, 
	 UFTRACE_MODE_LIVE,
	  UFTRACE_MODE_RECV 중 하나이면 함수를 / 종료합니다. 
	  default.opts 파일은 / 분석 명령에만 사용됩니다. 
	*/
	/* default.opts is only for analysis commands */
	if (opts->mode == UFTRACE_MODE_RECORD || opts->mode == UFTRACE_MODE_LIVE ||
	    opts->mode == UFTRACE_MODE_RECV)
		return;



	/*
	기본 옵션으로 인해 사용자가 / 제공한 시간 필터를 / 덮어쓰지 
	않도록 parsing_default_opts 를 / true 로 설정합니다. 
	*/
	/* this is not to override user given time-filter by default opts */
	parsing_default_opts = true;



	/*
	 opts_file 에 / opts->dirname 과 basename 을 / 결합하여 / 기본 옵션 
	파일의 경로를 / 저장합니다. stat 함수를 / 사용하여 / 파일 
	정보를 / 가져오고, 파일 크기가 / 0 보다 크면 디버그 메시지를 
	/ 출력하고 parse_opt_file 함수를 / 호출하여 / 기본 옵션 파일을 
	/ 파싱합니다. 
	*/
	snprintf(opts_file, PATH_MAX, "%s/%s", opts->dirname, basename);
	if (!stat(opts_file, &stbuf) && stbuf.st_size > 0) {
		pr_dbg("apply '%s' option file\n", opts_file);
		parse_opt_file(argc, argv, opts_file, opts);
	}


	/*
	그렇지 않으면 opts->dirname 이 UFTRACE_DIR_NAME 과 같고 현재 
	디렉토리에 / "info" 파일이 있으면 현재 
	디렉토리에서 default.opts 파일을 / 다시 시도합니다. stat 함수를 
	/ 사용하여 / 파일 정보를 / 가져오고, 파일 크기가 / 0 보다 
	크면 디버그 메시지를 / 출력하고 parse_opt_file 함수를 / 
	호출하여 / 기본 옵션 파일을 / 파싱합니다. 
	*/
	else if (!strcmp(opts->dirname, UFTRACE_DIR_NAME) && !access("./info", F_OK)) {
		/* try again applying default.opts in the current dir */
		if (!stat(basename, &stbuf) && stbuf.st_size > 0) {
			pr_dbg("apply './%s' option file\n", basename);
			parse_opt_file(argc, argv, basename, opts);
		}
	}
}



/*
 UNIT_TEST 가 / 정의되지 않은 / 경우에만 main 함수가 / 
정의됩니다. 이 함수는 / 프로그램의 진입점입니다. argc 는 / 
명령줄 인자의 개수이고, argv 는 / 명령줄 인자 배열입니다. 
*/
#ifndef UNIT_TEST
int main(int argc, char *argv[])
{

	/*
	 uftrace_opts 구조체를 / 초기화합니다. 각 필드는 / 프로그램의 
	기본 설정을 / 정의합니다. 
	*/
	struct uftrace_opts opts = {

		// 프로그램 모드를 / 무효로 초기화합니다. 
		.mode = UFTRACE_MODE_INVALID,

		// 디렉토리 이름을 / UFTRACE_DIR_NAME 으로 초기화합니다. 
		.dirname = UFTRACE_DIR_NAME,

		// 라이브러리 호출을 / 추적하도록 설정합니다. 
		.libcall = true,

		//  공유 메모리 버퍼 크기를 / SHMEM_BUFFER_SIZE 로 설정합니다. 
		.bufsize = SHMEM_BUFFER_SIZE,


		// 최대 스택 깊이를 / OPT_RSTACK_DEFAULT 로 설정합니다.
		.max_stack = OPT_RSTACK_DEFAULT,


		// 수신 포트를 / UFTRACE_RECV_PORT 로 설정합니다. 
		.port = UFTRACE_RECV_PORT,

		// 페이저 사용을 / 설정합니다. 
		.use_pager = true,

		// 색상 모드를 / 자동으로 설정합니다. 
		.color = COLOR_AUTO, /* turn on if terminal */


		// 열 오프셋을 / OPT_COLUMN_OFFSET 로 설정합니다. 
		.column_offset = OPT_COLUMN_OFFSET,

		// 주석을 / 표시하도록 설정합니다. 
		.comment = true,

		// 커널 추적을 / 건너뛰도록 설정합니다. 
		.kernel_skip_out = true,


		// 필드를 / 초기화하지 않습니다. 
		.fields = NULL,

		// 정렬 열을 / OPT_SORT_COLUMN 으로 설정합니다. 
		.sort_column = OPT_SORT_COLUMN,

		// 이벤트 추적을 / 건너뛰도록 설정합니다. 
		.event_skip_out = true,

		// 패턴 유형을 / 정규 표현식으로 설정합니다. 
		.patt_type = PATT_REGEX,

		// 인수를 / 표시하도록 설정합니다. 
		.show_args = true,


		// 시계 소스를 / "mono"로 설정합니다. 
		.clock = "mono",
	};


	/*
	 ret 변수는 / 반환 값을 / 저장하며, 
	 초기값은 / -1 입니다. 
	 pager 변수는 / 페이저 프로그램을 / 가리키는 / 
	포인터로, 초기값은 / NULL 입니다. 
	*/
	int ret = -1;
	char *pager = NULL;





	/*
	 pr_* 함수들을 / 호출하기 전에 / logfp 와 outfp 를 / 
	각각 stderr 와 stdout 으로 설정합니다. 이는 / 로그와 출력 
	메시지를 / 적절한 파일 포인터에 / 출력하기 위함입니다. 
	*/
	/* this must be done before calling pr_*() */
	logfp = stderr;
	outfp = stdout;



	/*
	명령줄 인자의 개수가 / 1(즉, 프로그램 이름만 제공된 
	경우)이면 사용법과 푸터 메시지를 / 출력하고 프로그램을 / 
	종료합니다. 
	*/
	if (argc == 1) {
		pr_out(uftrace_usage);
		pr_out(uftrace_footer);
		return 0;
	}



	/*
	 parse_options 함수를 / 호출하여 / 명령줄 옵션을 / 파싱하고, 
	 그 반환 값을 / 기반으로 switch 문을 / 사용하여 / 분기합니다. 
	*/
	switch (parse_options(argc, argv, &opts)) {


	/*
	 parse_options 함수가 / -1 을 / 반환하면 
	 ret 을 / 0 으로 설정하고, cleanup 레이블로 이동합니다. 
	*/
	case -1:
		ret = 0;
		goto cleanup;


	/*
	 parse_options 함수가 / -2 를 / 반환하면 
	 사용법과 푸터 메시지를 / 출력하고, 
	 ret 을 / 0 으로 설정한 후 cleanup 레이블로 
	이동합니다. 
	*/
	case -2:
		pr_out(uftrace_usage);
		pr_out(uftrace_footer);
		ret = 0;
		goto cleanup;




	/*
	 parse_options 함수가 / -3 을 / 반환하면 opts.use_pager 가 / 
	true 인지 확인하고, true 이면 페이저를 / 시작합니다. 그런 
	다음 사용법과 도움말 메시지를 / 출력하고, 페이저가 / 종료될 
	때까지 기다립니다. ret 을 / 0 으로 설정한 후 cleanup 레이블로 
	이동합니다. 
	*/
	case -3:
		if (opts.use_pager)
			start_pager(setup_pager());
		pr_out(uftrace_usage);
		pr_out(uftrace_help);
		wait_for_pager();
		ret = 0;
		goto cleanup;
	}


	/*
	 opts.opt_file 가 / 설정되어 있으면 
	 parse_opt_file 함수를 / 호출하여 / 옵션 파일을 / 파싱합니다. 
	*/
	if (opts.opt_file)
		parse_opt_file(&argc, &argv, opts.opt_file, &opts);




	/*
	 opts.exename 이 NULL 이고 opts.list_event 가 / 
	false 이면 opts.mode 값을 / 확인합니다. opts.mode 가 / 
	UFTRACE_MODE_RECORD, 
	UFTRACE_MODE_LIVE, 
	UFTRACE_MODE_INVALID 중 하나이면 
	사용법과 푸터 메시지를 / 출력하고, ret 을 / 1로 설정한 후
	 cleanup 레이블로 이동합니다. 
	*/
	if (opts.exename == NULL && !opts.list_event) {
		switch (opts.mode) {
		case UFTRACE_MODE_RECORD:
		case UFTRACE_MODE_LIVE:
		case UFTRACE_MODE_INVALID:
			pr_out(uftrace_usage);
			pr_out(uftrace_footer);
			ret = 1;
			goto cleanup;
		}
	}



	/*
	 opts.mode 가 / UFTRACE_MODE_INVALID 이면
	  opts.mode 를 / UFTRACE_MODE_DEFAULT 로 설정합니다. 
	*/
	if (opts.mode == UFTRACE_MODE_INVALID)
		opts.mode = UFTRACE_MODE_DEFAULT;


	/*
	dbg_domain_set 이 true 이고 debug 가 / 0 이면
	 debug 를 / 1 로 설정합니다. 
	*/
	if (dbg_domain_set && !debug)
		debug = 1;






	/*
	opts.logfile 이 설정되어 있으면 로그 파일을 / append 모드로 
	엽니다. 파일을 / 열 수 없으면 logfp 를 / stderr 로 설정하고 
	오류 메시지를 / 출력합니다. 그런 다음 setvbuf 함수를 / 
	사용하여 / 로그 파일에 / 대해 라인 버퍼링을 / 설정합니다. 
	*/
if (opts.logfile) {  // opts.logfile이 설정되었는지 확인. 로그 파일이 설정된 경우에만 파일 작업을 진행.
    char *logfile_path = NULL;  // 로그 파일의 경로를 저장할 포인터 변수 선언 및 초기화.

    if(create_directory(opts.dirname) < 0) {  // opts.dirname 디렉터리를 생성. 실패하면 음수를 반환.
        ret = -1;  // 오류를 나타내기 위해 ret에 -1을 설정.
        goto cleanup;  // 오류 발생 시 cleanup 레이블로 이동하여 정리 작업을 수행.
    }

    xasprintf(&logfile_path, "%s/%s", opts.dirname, opts.logfile);  
    // 로그 파일의 전체 경로를 생성. opts.dirname(디렉토리 경로)와 opts.logfile(파일 이름)을 결합하여 경로를 생성.

    logfp = fopen(logfile_path, "a");  // 로그 파일을 "a" 모드(추가 모드)로 엶. logfp는 파일 포인터.

    if (logfp == NULL) {  // 만약 파일 열기에 실패한 경우.
        logfp = stderr;  // logfp를 표준 에러 출력(stderr)으로 설정하여 로그 메시지를 출력.
        pr_err("cannot open log file");  // "cannot open log file" 오류 메시지를 출력.
    }

    setvbuf(logfp, NULL, _IOLBF, 1024);  
    // 로그 파일의 버퍼링 모드를 설정. _IOLBF는 줄 단위 버퍼링을 의미하며, 버퍼 크기는 1024 바이트.
}


	/*
	opts.logfile 이 설정되지 않았고 debug 가 / true 이면 outfp 에 / 
	대해 라인 버퍼링을 / 설정하여 / 일반 출력과 디버그 메시지가 
	/ 섞이지 않도록 합니다. 
	*/
	else if (debug) {
		/* ensure normal output is not mixed by debug message */
		setvbuf(outfp, NULL, _IOLBF, 1024);
	}




	// debug 가 / true이면 d 변수를 / 선언합니다. 
	if (debug) {
		int d;



		/*
		 모든 디버그 도메인에 / 대해 기본 디버그 수준을 / 
		설정합니다. dbg_domain[d]가 / -1이거나 dbg_domain_set 이 
		false 이면 dbg_domain[d]를 / debug 로 설정합니다. 
		*/
		/* set default debug level */
		for (d = 0; d < DBG_DOMAIN_MAX; d++) {
			if (dbg_domain[d] == -1 || !dbg_domain_set)
				dbg_domain[d] = debug;
		}
	}



	/*
	 uftrace_version 을 / 사용하여 / 디버그 메시지를 / 출력합니다. 
	이는 / 현재 실행 중인 uftrace 의 버전을 / 표시합니다. 
	*/
	pr_dbg("running %s\n", uftrace_version);





	/*
	opts.kernel_skip_out 과 
	opts.event_skip_out 값을 / 
	opts.range.kernel_skip_out 과 
	opts.range.event_skip_out 에 / 각각 
	설정합니다. 
	*/
	opts.range.kernel_skip_out = opts.kernel_skip_out;
	opts.range.event_skip_out = opts.event_skip_out;





	/*
	opts.mode 가 / UFTRACE_MODE_RECORD, 
	UFTRACE_MODE_RECV, 
	UFTRACE_MODE_TUI 중 하나이면 
	opts.use_pager 를 / false 로 설정합니다. 
	opts.nop 이 true 이면 opts.use_pager 를 / false 로 설정합니다. 
	*/
	if (opts.mode == UFTRACE_MODE_RECORD || opts.mode == UFTRACE_MODE_RECV ||
	    opts.mode == UFTRACE_MODE_TUI)
		opts.use_pager = false;
	if (opts.nop)
		opts.use_pager = false;



	/*
	opts.use_pager 가 / true 이면 setup_pager 함수를 / 호출하여 / 
	페이저를 / 설정하고 pager 변수에 / 저장합니다. 
	*/
	if (opts.use_pager)
		pager = setup_pager();




	/*
	opts.pid 가 / 설정되지 않은 / 경우(클라이언트 모드에서 
	미설정된 값을 / 유지), opts.depth 가 / 설정되지 
	않으면 opts.depth 를 / OPT_DEPTH_DEFAULT 로 설정합니다. 
	*/
	if (!opts.pid) { /* Keep uninitialized values in client mode */
		if (!opts.depth)
			opts.depth = OPT_DEPTH_DEFAULT;
	}




	/*
	 setup_color 함수를 / 호출하여 / 색상 설정을 / 
	초기화하고, setup_signal 함수를 / 호출하여 / 신호 설정을 / 
	초기화합니다. 
	*/
	setup_color(opts.color, pager);
	setup_signal();




	/*
	 opts.use_pager 가 / true 이고 
	 opts.mode 가 / UFTRACE_MODE_LIVE 가 / 아니면 
	 start_pager 함수를 / 호출하여 / 페이저를 / 시작합니다. 
	*/
	/* 'live' will start pager at its replay time */
	if (opts.use_pager && opts.mode != UFTRACE_MODE_LIVE)
		start_pager(pager);




	/*
	opts.mode 가 / UFTRACE_MODE_TUI 이면
	 opts.srcline 을 / true 로 설정합니다.
	  이는 / TUI 상태 줄에 / 소스 코드 라인 정보를 / 표시하기 위함입니다. 
	*/
	/* the srcline info is used for TUI status line by default */
	if (opts.mode == UFTRACE_MODE_TUI)
		opts.srcline = true;




	/*
	 opts.pid 가 / 설정되지 않은 / 경우(클라이언트 모드에서 
	미설정된 값을 / 유지), opts.trace 가 / 
	TRACE_STATE_NONE 이면 opts.trace 를 / TRACE_STATE_ON 으로 설정합니다. 
	*/
	if (!opts.pid) { /* Keep uninitialized values in client mode */
		if (opts.trace == TRACE_STATE_NONE)
			opts.trace = TRACE_STATE_ON;
	}


	/*
	분석 명령어에 / 대해 default.opts 옵션을 / 적용하기 
	위해 apply_default_opts 함수를 / 호출합니다. 이 함수는 / 기본 
	옵션 파일을 / 파싱하고, 명령줄 인자에 / 추가합니다. 
	*/
	/* apply 'default.opts' options for analysis commands */
	apply_default_opts(&argc, &argv, &opts);


	/*
	 opts.idx 가 / 0 이면 opts.idx 를 / argc 로 설정합니다. 
	*/
	if (opts.idx == 0)
		opts.idx = argc;



	/*
	 argc 와 argv 를 / opts.idx 만큼 감소시킵니다. 
	 이는 / 명령줄 인자를 
	 / 실제 명령어와 인자만 남기도록 조정하는 / 것입니다.
	*/
	argc -= opts.idx;
	argv += opts.idx;




	/*
	 opts.libcall 이 false 이고 opts.nest_libcall 이 true이면 오류 
	메시지를 / 출력합니다. --no-libcall 옵션과 --nest-libcall 옵션은 / 
	동시에 / 사용할 수 없음을 / 나타냅니다. 
	*/
	if (!opts.libcall && opts.nest_libcall)
		pr_err_ns("cannot use --no-libcall and --nest-libcall options together\n");




	/*
	opts.mode 에 / 따라 다른 명령어 함수를 / 호출하는 / switch 문을 
	/ 시작합니다. 
	*/
	switch (opts.mode) {


	/*
	 opts.mode 가 / UFTRACE_MODE_RECORD 이면 
	 command_record 함수를 / 호출하여 / 기록 모드를 / 실행하고,
	  반환 값을 / ret 에 / 저장합니다. 
	*/
	case UFTRACE_MODE_RECORD:
		ret = command_record(argc, argv, &opts);
		break;


	/*
	 opts.mode 가 / UFTRACE_MODE_REPLAY 이면 
	 command_replay 함수를 / 호출하여 / 재생 모드를 / 실행하고,
	  반환 값을 / ret 에 / 저장합니다. 
	*/
	case UFTRACE_MODE_REPLAY:
		ret = command_replay(argc, argv, &opts);
		break;

	
	/*
	opts.mode 가 / UFTRACE_MODE_LIVE 이면 
	/command_live 함수를 / 호출하여 
	/ 라이브 모드를 / 실행하고, 
	반환 값을 / ret 에 / 저장합니다. 
	*/
	case UFTRACE_MODE_LIVE:
		ret = command_live(argc, argv, &opts);
		break;


	/*
	 opts.mode 가 / UFTRACE_MODE_REPORT 이면
	  command_report 함수를 / 호출하여 / 
	  보고서 모드를 / 실행하고, 반환 값을 / ret 에 / 
	저장합니다. 
	*/
	case UFTRACE_MODE_REPORT:
		ret = command_report(argc, argv, &opts);
		break;


	/*
	 opts.mode 가 / UFTRACE_MODE_INFO 이면 
	 command_info 함수를 / 호출하여 
	/ 정보 모드를 / 실행하고, 반환 값을 / ret 에 / 저장합니다. 
	*/
	case UFTRACE_MODE_INFO:
		ret = command_info(argc, argv, &opts);
		break;




	/*
	 opts.mode 가 / UFTRACE_MODE_RECV 이면 
	 command_recv 함수를 / 호출하여 
	/ 수신 모드를 / 실행하고, 반환 값을 / ret 에 / 저장합니다.
	*/
	case UFTRACE_MODE_RECV:
		ret = command_recv(argc, argv, &opts);
		break;



	/*
	 opts.mode 가 / UFTRACE_MODE_DUMP 이면 
	 command_dump 함수를 / 호출하여 
	/ 덤프 모드를 / 실행하고, 반환 값을 / ret 에 / 저장합니다. 
	*/
	case UFTRACE_MODE_DUMP:
		ret = command_dump(argc, argv, &opts);
		break;


	/*
	opts.mode 가 / UFTRACE_MODE_GRAPH 이면 
	command_graph 함수를 / 호출하여 
	/ 그래프 모드를 / 실행하고, 반환 값을 / ret 에 / 저장합니다. 
	*/
	case UFTRACE_MODE_GRAPH:
		ret = command_graph(argc, argv, &opts);
		break;




	/*
	opts.mode 가 / UFTRACE_MODE_SCRIPT 이면 
	command_script 함수를 / 	호출하여 
	 스크립트 모드를 / 실행하고, 반환 값을 / ret 에 / 
	저장합니다. 
	*/
	case UFTRACE_MODE_SCRIPT:
		ret = command_script(argc, argv, &opts);
		break;


	
	/*
	 opts.mode 가 / UFTRACE_MODE_TUI 이면
	  command_tui 함수를 / 호출하여 / 
	TUI 모드를 / 실행하고, 반환 값을 / ret 에 / 저장합니다. 
	*/
	case UFTRACE_MODE_TUI:
		ret = command_tui(argc, argv, &opts);
		break;


	// opts.mode 가 / UFTRACE_MODE_INVALID 이면 ret 을 / 1 로 설정합니다. 
	case UFTRACE_MODE_INVALID:
		ret = 1;
		break;
	}



	/*
	 wait_for_pager 함수를 / 호출하여 / 페이저가 / 종료될 때까지 
	대기합니다. 
	*/
	wait_for_pager();


/*
 cleanup 레이블을 / 정의합니다.
  이 레이블은 / goto 문에 / 의해 
점프될 수 있는 / 위치입니다. 
*/
cleanup:

	// opts.logfile 이 설정되어 있으면 logfp 파일 포인터를 / 닫습니다.
	if (opts.logfile)
		fclose(logfp);


	/*
	 opts.opt_file 이 설정되어 있으면 
	 argv - opts.idx 를 / 사용하여 / 
	명령줄 인자로 할당된 메모리를 / 해제합니다. 
	*/
	if (opts.opt_file)
		free_parsed_cmdline(argv - opts.idx);



	/*
	free_opts 함수를 / 호출하여 / 
	opts 구조체에 / 할당된 모든 동적 
	메모리를 / 해제합니다. 
	*/
	free_opts(&opts);

	//  ret 값을 / 반환하며 main 함수를 / 종료합니다. 
	return ret;
}


/*
#else 블록은 / UNIT_TEST 가 / 정의된 경우에만 실행됩니다. 
여기서 OPT_FILE 매크로를 / "opt"로 정의합니다. 
*/
#else
#define OPT_FILE "opt"


//  option_parsing1 이라는 / 이름의 테스트 케이스를 / 정의합니다. 
TEST_CASE(option_parsing1)
{


	/*
	 stropt 라는 / 문자열 포인터를 / NULL 로 초기화합니다.
	  i 라는 / 정수형 변수와 elapsed_time 이라는 / 불리언 변수를 / 선언합니다. 
	*/
	char *stropt = NULL;
	int i;
	bool elapsed_time;


	/*
	"check parsing size suffix"라는 / 디버그 메시지를 / 
	출력합니다.
	*/
	pr_dbg("check parsing size suffix\n");


	/*
	 parse_size 함수를 / 테스트합니다. 
	 parse_size("1234")의 결과가 / 
	1234 인지, parse_size("10k")의 결과가 / 
	10240 인지, parse_size("100M")의 결과가 / 100 * 1024 * 1024 인지 
	확인합니다. TEST_EQ 매크로를 / 사용하여 / 기대값과 실제값이 
	동일한지 검사합니다. 
	*/
	TEST_EQ(parse_size("1234"), 1234);
	TEST_EQ(parse_size("10k"), 10240);
	TEST_EQ(parse_size("100M"), 100 * 1024 * 1024);



	/*
	 "check string list addition"라는 / 디버그 메시지를 / 
	출력합니다. 
	*/
	pr_dbg("check string list addition\n");
	
	
	/*
	 opt_add_string 함수를 / 사용하여 / stropt 에 / "abc"를 / 
	추가합니다. 결과가 / "abc"인지 확인합니다. TEST_STREQ 매크로를 
	/ 사용하여 / 문자열이 일치하는지 검사합니다. 
	*/
	stropt = opt_add_string(stropt, "abc");
	TEST_STREQ(stropt, "abc");


	/*
	 opt_add_string 함수를 / 사용하여 / stropt 에 / "def"를 / 
	추가합니다. 결과가 / "abc;def"인지 
	확인합니다. TEST_STREQ 매크로를 / 사용하여 / 문자열이 
	일치하는지 검사합니다. 
	*/
	stropt = opt_add_string(stropt, "def");
	TEST_STREQ(stropt, "abc;def");


	/*
	 stropt 에 / 할당된 메모리를 / 해제하고, stropt 를 / NULL 로 
	설정합니다. 
	*/
	free(stropt);
	stropt = NULL;


	/*
	"check string list addition with prefix"라는 / 디버그 
	메시지를 / 출력합니다. 
	*/
	pr_dbg("check string list addition with prefix\n");


	/*
	 opt_add_prefix_string 함수를 / 사용하여 / stropt 에 / "!abc"를 / 
	추가합니다. 결과가 / "!abc"인지 확인합니다. 
	TEST_STREQ 매크로를 / 사용하여 / 문자열이 
	일치하는지 검사합니다. 
	*/
	stropt = opt_add_prefix_string(stropt, "!", "abc");
	TEST_STREQ(stropt, "!abc");


	/*
	 opt_add_prefix_string 함수를 / 사용하여 / stropt 에 / "?def"를 / 
	추가합니다. 결과가 / "!abc;?def"인지 
	확인합니다. TEST_STREQ 매크로를 / 사용하여 / 문자열이 
	일치하는지 검사합니다. 
	*/
	stropt = opt_add_prefix_string(stropt, "?", "def");
	TEST_STREQ(stropt, "!abc;?def");

	free(stropt);
	stropt = NULL;

	pr_dbg("check parsing colors\n");
	TEST_EQ(parse_color("1"), COLOR_ON);
	TEST_EQ(parse_color("true"), COLOR_ON);
	TEST_EQ(parse_color("off"), COLOR_OFF);
	TEST_EQ(parse_color("n"), COLOR_OFF);
	TEST_EQ(parse_color("auto"), COLOR_AUTO);
	TEST_EQ(parse_color("ok"), COLOR_UNKNOWN);

	pr_dbg("check parsing demanglers\n");
	TEST_EQ(parse_demangle("simple"), DEMANGLE_SIMPLE);
	TEST_EQ(parse_demangle("no"), DEMANGLE_NONE);
	TEST_EQ(parse_demangle("0"), DEMANGLE_NONE);
	/* full demangling might not supported */
	TEST_NE(parse_demangle("full"), DEMANGLE_SIMPLE);

	for (i = 0; i < DBG_DOMAIN_MAX; i++)
		dbg_domain[i] = 0;

	pr_dbg("check parsing debug domains\n");
	parse_debug_domain("mcount:1,uftrace:2,symbol:3");
	TEST_EQ(dbg_domain[DBG_UFTRACE], 2);
	TEST_EQ(dbg_domain[DBG_MCOUNT], 1);
	TEST_EQ(dbg_domain[DBG_SYMBOL], 3);

	TEST_EQ(parse_any_timestamp("1ns", &elapsed_time), 1ULL);
	TEST_EQ(parse_any_timestamp("2us", &elapsed_time), 2000ULL);
	TEST_EQ(parse_any_timestamp("3ms", &elapsed_time), 3000000ULL);
	TEST_EQ(parse_any_timestamp("4s", &elapsed_time), 4000000000ULL);
	TEST_EQ(parse_any_timestamp("5m", &elapsed_time), 300000000000ULL);

	return TEST_OK;
}

TEST_CASE(option_parsing2)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = {
		"uftrace", "replay", "-v",  "--data=abc.data", "--kernel", "-t", "1us", "-F",
		"foo",	   "-N",     "bar", "-Abaz@kernel",
	};
	int argc = ARRAY_SIZE(argv);
	int saved_debug = debug;

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);

	TEST_EQ(opts.mode, UFTRACE_MODE_REPLAY);
	TEST_EQ(debug, saved_debug + 1);
	TEST_EQ(opts.kernel, 1);
	TEST_EQ(opts.threshold, (uint64_t)1000);
	TEST_STREQ(opts.dirname, "abc.data");
	TEST_STREQ(opts.filter, "foo;!bar");
	TEST_STREQ(opts.args, "baz@kernel");

	free_opts(&opts);
	return TEST_OK;
}

TEST_CASE(option_parsing3)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = {
		"uftrace",
		"-v",
		"--opt-file",
		OPT_FILE,
	};
	int argc = ARRAY_SIZE(argv);
	char opt_file[] = "-K 2\n"
			  "-b4m\n"
			  "--column-view\n"
			  "--depth=3\n"
			  "t-abc";
	int file_argc;
	char **file_argv;
	FILE *fp;
	int saved_debug = debug;

	/* create opt-file */
	fp = fopen(OPT_FILE, "w");
	TEST_NE(fp, NULL);
	fwrite(opt_file, strlen(opt_file), 1, fp);
	fclose(fp);

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);
	TEST_STREQ(opts.opt_file, OPT_FILE);

	pr_dbg("check parsing option files\n");
	parse_opt_file(&file_argc, &file_argv, opts.opt_file, &opts);
	TEST_EQ(file_argc, 7); // +1 for dummy prefix

	unlink(OPT_FILE);

	TEST_EQ(opts.mode, UFTRACE_MODE_INVALID);
	TEST_EQ(debug, saved_debug + 1);
	TEST_EQ(opts.kernel, 1);
	TEST_EQ(opts.kernel_depth, 2);
	TEST_EQ(opts.depth, 3);
	TEST_EQ(opts.bufsize, 4 * 1024 * 1024);
	TEST_EQ(opts.column_view, 1);
	TEST_STREQ(opts.exename, "t-abc");

	free_parsed_cmdline(file_argv);
	free_opts(&opts);
	return TEST_OK;
}

TEST_CASE(option_parsing4)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = {
		"uftrace",
		"-v",
		"--opt-file",
		OPT_FILE,
	};
	int argc = ARRAY_SIZE(argv);
	char opt_file[] = "-K 2\n"
			  "# buffer size: 4 MB\n"
			  "-b4m\n"
			  "\n"
			  "## show different thread with different indentation\n"
			  "--column-view\n"
			  "\n"
			  "# limit maximum function call depth to 3\n"
			  "--depth=3 # same as -D3 \n"
			  "\n"
			  "\n"
			  "#test program\n"
			  "t-abc\n"
			  "\n";
	int file_argc;
	char **file_argv;
	FILE *fp;
	int saved_debug = debug;

	/* create opt-file */
	fp = fopen(OPT_FILE, "w");
	TEST_NE(fp, NULL);
	fwrite(opt_file, strlen(opt_file), 1, fp);
	fclose(fp);

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);
	TEST_STREQ(opts.opt_file, OPT_FILE);

	pr_dbg("check parsing option files\n");
	parse_opt_file(&file_argc, &file_argv, opts.opt_file, &opts);
	TEST_EQ(file_argc, 7); // +1 for dummy prefix

	unlink(OPT_FILE);

	pr_dbg("command mode should remain as is\n");
	TEST_EQ(opts.mode, UFTRACE_MODE_INVALID);
	TEST_EQ(debug, saved_debug + 1);
	TEST_EQ(opts.kernel, 1);
	TEST_EQ(opts.kernel_depth, 2);
	TEST_EQ(opts.depth, 3);
	TEST_EQ(opts.bufsize, 4 * 1024 * 1024);
	TEST_EQ(opts.column_view, 1);
	TEST_STREQ(opts.exename, "t-abc");

	free_parsed_cmdline(file_argv);
	free_opts(&opts);
	return TEST_OK;
}

TEST_CASE(option_parsing5)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = { "uftrace", "-v", "--opt-file", OPT_FILE, "hello" };
	int argc = ARRAY_SIZE(argv);
	char opt_file[] = "record\n"
			  "-F main\n"
			  "--time-filter 1us\n"
			  "--depth=3\n"
			  "t-abc";
	int file_argc = argc;
	char **file_argv = argv;
	FILE *fp;
	int saved_debug = debug;

	/* create opt-file */
	fp = fopen(OPT_FILE, "w");
	TEST_NE(fp, NULL);
	fwrite(opt_file, strlen(opt_file), 1, fp);
	fclose(fp);

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);
	TEST_STREQ(opts.opt_file, OPT_FILE);

	pr_dbg("check parsing option files\n");
	parse_opt_file(&file_argc, &file_argv, opts.opt_file, &opts);

	unlink(OPT_FILE);

	pr_dbg("opt file should update command mode\n");
	TEST_EQ(opts.mode, UFTRACE_MODE_RECORD);
	TEST_EQ(debug, saved_debug + 1);
	/* preserve original arg[cv] if command line is given */
	TEST_EQ(file_argc, argc);
	TEST_EQ(file_argv, (char **)argv);
	TEST_EQ(opts.threshold, (uint64_t)1000);
	TEST_EQ(opts.depth, 3);
	TEST_EQ(opts.idx, 4);
	TEST_STREQ(opts.filter, "main");
	/* it should not update exename to "t-abc" */
	TEST_STREQ(opts.exename, "hello");

	free_opts(&opts);
	return TEST_OK;
}

#endif /* UNIT_TEST */
