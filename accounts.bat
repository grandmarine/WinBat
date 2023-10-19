@echo off
ECHO ☆☆☆기술적 취약점 분석 평가 방법 상세가이드 2021.3. 기준☆☆☆
ECHO.
ECHO.

ECHO ●판단기준 W-02(상)
ECHO 양호 : Guest 계정이 비활성화 되어 있는 경우
ECHO 취약 : Guest 계정이 활성화 되어 있는 경우

ECHO.
ECHO ●현황
NET USER Guest > NUL
IF NOT ERRORLEVEL 1 net user guest | find /i "활성 계정"

ECHO.
ECHO ●결과
IF NOT ERRORLEVEL 1 net user guest | find /i "활성 계정" | find /i "예" > NUL
IF ERRORLEVEL 1 ECHO 양호
IF NOT ERRORLEVEL 1 ECHO 취약


ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-03(상)
ECHO 양호 : 불필요한 계정이 존재하지 않는 경우
ECHO 취약 : 불필요한 계정이 존재하는 경우

ECHO.
ECHO ●현황
NET USER |FIND /V "명령을 잘 실행했습니다."

ECHO.
ECHO ●결과
ECHO 인터뷰

ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.

ECHO ●판단기준 W-04(상)
ECHO 양호 : 계정 잠금 임계값이 5 이하의 값으로 설정되어 있는 경우
ECHO 취약 : 계정 잠금 임계값이 6 이상의 값으로 설정되어 있는 경우

ECHO.
ECHO ●현황
NET ACCOUNTS | FIND /I "잠금 임계값"

ECHO.
ECHO ●결과
NET ACCOUNTS | FINDSTR /I /C:"잠금 임계값" > 1-04-Threshold.txt
FOR /f "tokens=1-3" %%a IN (1-04-Threshold.txt) DO SET Threshold=%%c
IF %Threshold% LEQ 5 ECHO 양호
IF NOT %Threshold% LEQ 5 ECHO 취약

DEL 1-04-Threshold.txt

ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.