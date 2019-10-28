from winreg import *
import datetime

import os
import sys
import ctypes
import winreg


def is_running_as_admin():
    '''
    Checks if the script is running with administrative privileges.
    Returns True if is running as admin, False otherwise.
    '''
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def execute():
    if not is_running_as_admin():
        print('[!] The script is NOT running with administrative privileges')
        return True
    else:
        print('[+] The script is running with administrative privileges!')
        return False

def Collector(RootKey,Net, Element):
    fileName = get_file_name(Element)+'.txt'
    EnumList = []
    #net = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

    Key = CreateKey(RootKey, Net)

    f = open(fileName,'w')

    for x in range(1024):
        try:
            EnumList.append(EnumKey(Key,x))
        except:
            pass

    for i in EnumList:
        Key2 = CreateKey(RootKey,Net+'\\'+i)
        #print("\n\n----------"+i+"-----------\n")
        printSubTitle = "\n\n----------"+i+"-----------\n"
        f.write(printSubTitle)
        for y in range(1024):
            try:
                arr = list(EnumValue(Key2,y))
                #print(arr[0]+"\t"+arr[1]+"\t"+str(arr[2]))
                #print(arr[0]+"\t"+arr[1])
                printLine = arr[0]+"\t"+arr[1]+"\n"
                f.write(printLine)
            except:
                pass
    f.close()

def Collector_Sub(RootKey,Net, Element):
    fileName = get_file_name(Element) + '.txt'

    EnumList = []
    EnumList_sub =[]

    f = open(fileName, 'w')

    Key = CreateKey(RootKey, Net)

    for x in range(1024):
        try:
            EnumList.append(EnumKey(Key, x))
            Key2 = CreateKey(RootKey,Net+'\\'+EnumList[x])
            for y in range(1024):
                try:
                    EnumList_sub.append(EnumList[x]+ '\\'+EnumKey(Key2,y))
                except:
                    pass
        except:
            pass

    for i in EnumList_sub:
        Key3 = CreateKey(RootKey,Net+'\\'+i)
        printSubTitle = "\n\n----------" + i + "-----------\n"
        f.write(printSubTitle)
        #printSubTitle = "\n\n----------"+i+"-----------\n"
        for y in range(1024):
            try:
                arr = list(EnumValue(Key3,y))
                printLine = arr[0] + "\t" + arr[1] + "\n"
                f.write(printLine)
            except:
                pass
    f.close()

def Collector_Temp(RootKey,Net, Element):
    #fileName = get_file_name(Element)+'.txt'
    EnumList = []

    Key = CreateKey(RootKey, Net)

    #f = open(fileName,'w')

    for x in range(1024):
        try:

            EnumList.append(EnumKey(Key,x))
        except:
            pass

    for i in EnumList:
        #Key2 = CreateKey(RootKey,Net+'\\'+i)
        print("\n\n----------"+i+"-----------\n")
        try:
            arr = list(EnumValue(Key2, y))
            # print(arr[0]+"\t"+arr[1]+"\t"+str(arr[2]))
            print(arr[0] + "\t" + arr[1])
            # printLine = arr[0]+"\t"+arr[1]+"\n"
            # f.write(printLine)
        except:
            pass
        #printSubTitle = "\n\n----------"+i+"-----------\n"
        #f.write(printSubTitle)

    #f.close()

def get_file_name(name):
     today = datetime.datetime.today()
     return str(today.year)+ str(today.month)+ str(today.day)+ str(today.hour)+ str(today.minute)+ str(today.second)+"_"+name

if __name__ == '__main__':
     ##루트키 + 경로 + 이름 -> 추출 및 파일 출력

     ## -----------------------사용자 비밀번호 설정 확인-----------------------------

     ## SAM 관리자 권한으로도 안됌
     #Collector(HKEY_LOCAL_MACHINE,"SECURITY\\SAM\\SAM","SAM")

     #비밀번호 설정 확인 -> DisablePasswordChange, MaximumPasswordAge 항목을 보면 됌 -> 값은 가져옴
     Collector(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SecEdit\\Reg Values", "DisablePasswordChange")

     #수정이 필요 -> Netlogon까지는 값은 가져옴  / Parameters -> 값 못가져옴
     #Collector(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Netlogon\\Parameters", "Netlogon_Parameters")
     Collector(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Netlogon", "Netlogon_Parameters")

     ## -----------------------------------------------------------------------------

     ## -----------------------운영체제 최신 버전 확인-----------------------------
     ## --> 어떤 것으로 판단할지를 봐야함 -> 값은 가져옴
     Collector(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","CurrentVersion")

     ## -----------------------------------------------------------------------------

     ## -----------------------보안시스템(백신 등) 설치 확인-----------------------------
     ## --> 어떤 것으로 판단할지를 봐야함 -> 항목은 있지만 못가져옴 // 확인필요
     #Collector(HKEY_CURRENT_USER, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "SecuritySystem")
     ## Unistall -> 중복
     Collector(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SecurityUninstall")
     ## -----------------------------------------------------------------------------

     ## -----------------------보안시스템(백신 등) 해지 확인-----------------------------
     ## --> 어떤 것으로 판단할지를 봐야함 -> 항목은 있지만 못가져옴 // 확인필요
     #Collector_Temp(HKEY_CURRENT_USER, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "SecuritySystem")
     ## Unistall -> 중복
     # Collector(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SecurityUninstall")
     ## -----------------------------------------------------------------------------

     ## -----------------------(이동식) 저장매체 연결 흔적 확인-----------------------------
     ## 이진 값이 있지만 가져오지 못함. 확인 필요
     # Collector(HKEY_LOCAL_MACHINE, "SYSTEM\\MountedDevices", "MountedDevices")
     ## 하위 - sub
     Collector_Sub(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "USBSTOR")
     ## 하위 - sub / 바로 위와 같은 값
     ###Collector_Sub(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", "USBSTOR2")

     ## -----------------------------------------------------------------------------
     ## -----------------------고정형 저장장치 연결 흔적 확인-----------------------------
     ## 이진 값이 있지만 가져오지 못함. 확인 필요
     # Collector(HKEY_LOCAL_MACHINE, "SYSTEM\\MountedDevices", "MountedDevices")
     ## 하위 - sub
     ###Collector_Sub(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "USBSTOR")
     ## -----------------------------------------------------------------------------

     ## -----------------------응용프로그램 최신버전확인-----------------------------
     ## 하위 - sub
     Collector_Sub(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\ROOT", "Driver")

## Unistall -> 정상 작동함
     #Collector(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall","Uninstall")



##   경로 입력시 확인 가능
#    Collector("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
#    Collector_SAM("SECURITY\\SAM\\SAM")

## 관리자 권한 확인 후 SAM 레지스트리 접근 - But, 권한 오류 있음
#    if(execute()):
#        exit()
#    else:
#        Collector_SAM("SECURITY\\SAM\\SAM")