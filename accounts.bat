@echo off
ECHO �١١ٱ���� ����� �м� �� ��� �󼼰��̵� 2021.3. ���ء١١�
ECHO.
ECHO.

ECHO ���Ǵܱ��� W-02(��)
ECHO ��ȣ : Guest ������ ��Ȱ��ȭ �Ǿ� �ִ� ���
ECHO ��� : Guest ������ Ȱ��ȭ �Ǿ� �ִ� ���

ECHO.
ECHO ����Ȳ
NET USER Guest > NUL
IF NOT ERRORLEVEL 1 net user guest | find /i "Ȱ�� ����"

ECHO.
ECHO �ܰ��
IF NOT ERRORLEVEL 1 net user guest | find /i "Ȱ�� ����" | find /i "��" > NUL
IF ERRORLEVEL 1 ECHO ��ȣ
IF NOT ERRORLEVEL 1 ECHO ���


ECHO.
ECHO ������������������������������������������������������
ECHO.


ECHO ���Ǵܱ��� W-03(��)
ECHO ��ȣ : ���ʿ��� ������ �������� �ʴ� ���
ECHO ��� : ���ʿ��� ������ �����ϴ� ���

ECHO.
ECHO ����Ȳ
NET USER |FIND /V "����� �� �����߽��ϴ�."

ECHO.
ECHO �ܰ��
ECHO ���ͺ�

ECHO.
ECHO ������������������������������������������������������
ECHO.

ECHO ���Ǵܱ��� W-04(��)
ECHO ��ȣ : ���� ��� �Ӱ谪�� 5 ������ ������ �����Ǿ� �ִ� ���
ECHO ��� : ���� ��� �Ӱ谪�� 6 �̻��� ������ �����Ǿ� �ִ� ���

ECHO.
ECHO ����Ȳ
NET ACCOUNTS | FIND /I "��� �Ӱ谪"

ECHO.
ECHO �ܰ��
NET ACCOUNTS | FINDSTR /I /C:"��� �Ӱ谪" > 1-04-Threshold.txt
FOR /f "tokens=1-3" %%a IN (1-04-Threshold.txt) DO SET Threshold=%%c
IF %Threshold% LEQ 5 ECHO ��ȣ
IF NOT %Threshold% LEQ 5 ECHO ���

DEL 1-04-Threshold.txt

ECHO.
ECHO ������������������������������������������������������
ECHO.