#include <stdio.h>
#include <stdlib.h>
#include <limits.h>  // PATH_MAX 상수를 사용하기 위해 추가

int main() {
    FILE *file;
    char filename[PATH_MAX] = "output.txt"; // 파일 이름 설정
		snprintf(filename, sizeof(filename), "%s/%s","kimrihyeon","logfile.txt");
    // 파일을 append 모드로 열거나 생성
    file = fopen(filename, "a");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    // 파일 스트림에 대해 라인 버퍼링 모드 설정 (1024 바이트 버퍼)
    if (setvbuf(file, NULL, _IOLBF, 1024) != 0) {
        perror("Error setting buffer");
        fclose(file);
        return EXIT_FAILURE;
    }

    // 파일에 내용 기록 (버퍼링된 후 플러시됨)
    fprintf(file, "This is a test log entry.\n");
    fprintf(file, "Another log entry.\n");

    // 파일 닫기
    fclose(file);

    printf("File '%s' has been created and written to.\n", filename);

    return EXIT_SUCCESS;
}

