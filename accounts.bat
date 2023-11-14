@ECHO OFF
TITLE 기술적 취약점 분석 평가 방법 상세가이드 2021.3. 기준
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


ECHO ●판단기준 W-05(상)
ECHO 양호 : "해독 가능한 암호화를 사용하여 암호 저장" 정책이 "사용 안 함" 으로 되어 있는 경우
ECHO 취약 : "해독 가능한 암호화를 사용하여 암호 저장" 정책이 "사용" 으로 되어 있는 경우

ECHO.
ECHO ●현황
secedit /export /cfg LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "ClearTextPassword"


ECHO.
ECHO ●결과
TYPE LocalSecurityPolicy.txt | find /i "ClearTextPassword = 1" > NUL
IF ERRORLEVEL 1 ECHO 양호
IF NOT ERRORLEVEL 1 ECHO 취약

ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-06(상)
ECHO 양호 : Administrators 그룹의 구성원을 1명 이하로 유지하거나 불필요한 관리자 계쩡이 존재하지 않는 경우
ECHO 취약 : Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우 

ECHO.
ECHO ●현황
net localgroup administrators | find /v "명령을 잘 실행했습니다."

ECHO.
ECHO ●결과
ECHO 인터뷰

ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-46(중)
ECHO 양호 : "Everyone 사용 권한을 익명 사용자에게 적용" 정책이 "사용 안 함" 으로 되어 있는 경우
ECHO 취약 : "Everyone 사용 권한을 익명 사용자에게 적용" 정책이 "사용" 으로 되어 있는 경우

ECHO.
ECHO ●현황
secedit /export /cfg LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "EveryoneIncludesAnonymous" 

ECHO.
ECHO ●결과
TYPE LocalSecurityPolicy.txt | find /i "EveryoneIncludesAnonymous" | find "4,0" > NUL
IF ERRORLEVEL 1 ECHO 취약
IF NOT ERRORLEVEL 1 ECHO 양호 
ECHO.


ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-47(중)
ECHO 양호 : "계정 잠금 기간" 및 "계정 잠금 기간 원래대로 설정 기간"이 설정되어 있는 경우
ECHO 취약 : "계정 잠금 기간" 및 "계정 잠금 기간 원래대로 설정 기간"이 설정되지 않는 경우

ECHO.
ECHO.
ECHO ●현황
net accounts | findstr /I /C:"잠금 기간"
net accounts | findstr /I /C:"잠금 관찰 창"

ECHO.
ECHO ●결과
net accounts | findstr /I /C:"잠금 기간" >> 1-08-LockTime.txt
FOR /f "tokens=1-6" %%a IN (1-08-LockTime.txt) DO SET LockTime=%%d

net accounts | findstr /I /C:"잠금 관찰 창" >> 1-08-LockReTime.txt
FOR /f "tokens=1-6" %%a IN (1-08-LockReTime.txt) DO SET LockReTime=%%e

IF %LockTime% GEQ 60 IF %LockReTime% GEQ 60 GOTO 1-08-Y

:1-08-N
ECHO 취약
GOTO 1-08-END

:1-08-Y
ECHO 양호
GOTO 1-08-END

:1-08-END
DEL 1-08-LockTime.txt
DEL 1-08-LockReTime.txt

ECHO.
ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.

ECHO ●판단기준 W-48(중)
ECHO 양호 : "암호는 복잡성을 만족해야 함" 정책이 "사용" 으로 되어 있는 경우
ECHO 취약 : "암호는 복잡성을 만족해야 함" 정책이 "사용 안 함" 으로 되어 있는 경우

ECHO.
ECHO.
ECHO ●현황
secedit /EXPORT /CFG LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "PasswordComplexity"

ECHO.
ECHO.
ECHO ●결과
TYPE LocalSecurityPolicy.txt | find /i "PasswordCompleyxity" | find "1" > NUL
IF ERRORLEVEL 1 ECHO 취약
IF NOT ERRORLEVEL 1 ECHO 양호

DEL LocalSecurityPolicy.txt

ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.

ECHO ●판단기준 W-49(중)
ECHO 양호 : "최소 암호 길이"가 "8문자" 이상으로 설정되어 있는 경우
ECHO 취약 : "최소 암호 길이"가 "8문자" 이상으로 설정되지 않았거나 "8문자" 미만으로 설정되어 있는 경우

ECHO.
ECHO ●현황
secedit /EXPORT /CFG LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "MinimumPasswordLength"

ECHO.
ECHO ●결과
TYPE LocalSecurityPolicy.txt | find "MinimumPasswordLength =" > passwd.txt
FOR /f "tokens=1-3" %%a IN (passwd.txt) DO SET passwd_length=%%c
IF %passwd_length% GEQ 8 ECHO 양호
IF NOT %passwd_length% GEQ 8 ECHO 취약

DEL LocalSecurityPolicy.txt
DEL passwd.txt

ECHO.
ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-50(중)
ECHO 양호 : "최대 암호 사용 기간"이 "90일" 이하로 설정되어 있는 경우
ECHO 취약 : "최대 암호 사용 기간"이 설정되지 않았거나 "90일"을 초과하는 값으로 설정된 경우
ECHO.

ECHO ●현황
secedit /EXPORT /CFG LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "MaximumPasswordAge" | find /v "\"

ECHO.
ECHO ●결과
TYPE LocalSecurityPolicy.txt | find "MaximumPasswordAge =" > passwd.txt
FOR /f "tokens=1-3" %%a IN (passwd.txt) DO SET passwd_maxage=%%c
IF %passwd_maxage% LEQ 90 ECHO 양호
IF NOT %passwd_maxage% LEQ 90 ECHO 취약

DEL LocalSecurityPolicy.txt
DEL passwd.txt

ECHO.
ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-51(중)
ECHO 양호 : "최소 암호 사용 기간"이 0보다 큰 값으로 설정되어 있는 경우
ECHO 취약 : "최소 암호 사용 기간"이 0으로 설정되어 있는 경우
ECHO.

ECHO ●현황
secedit /EXPORT /CFG LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "MinimumPasswordAge"

ECHO.
ECHO ●결과

TYPE LocalSecurityPolicy.txt | find "MinimumPasswordAge =" > passwd.txt
FOR /f "tokens=1-3" %%a IN (passwd.txt) DO SET passwd_minage=%%c
IF %passwd_minage% GEQ 1 ECHO 양호
IF NOT %passwd_minage% GEQ 1 ECHO 취약

DEL LocalSecurityPolicy.txt
DEL passwd.txt

ECHO.
ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-52(중)
ECHO 양호 : "마지막 사용자 이름 표시 안 함"이 "사용"으로 설정되어 있는 경우
ECHO 취약 : "마지막 사용자 이름 표시 안 함"이 "사용 안 함"으로 설정되어 있는 경우
ECHO.

ECHO ●현황
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /I "DontDisplayLastUserName"

ECHO ●결과
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /I "DontDisplayLastUserName" | find "1" > NUL
IF NOT ERRORLEVEL 1 ECHO 양호
IF ERRORLEVEL 1 ECHO 취약

ECHO.
ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.


ECHO ●판단기준 W-53(중)
ECHO 양호 : "로컬 로그온 허용 정책"에 Administrator, IUSR_만 존재하는 경우
ECHO 취약 : "로컬 로그온 허용 정책"에 Administrator, IUSR_외 다른 계정 및 그룹이 존재하는 경우
ECHO.

ECHO ●현황
secedit /EXPORT /CFG LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "SeInteractiveLogonRight"

ECHO.
ECHO ●결과
ECHO 인터뷰

ECHO.
ECHO.
ECHO □□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□
ECHO.









PAUSE






