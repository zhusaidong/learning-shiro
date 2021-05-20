package com.example.shiro.contoller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zhusaidong
 */
@RestController
public class HomeController{
    @RequestMapping("/home/test")
    @RequiresPermissions("user:test")
    public String test(){
        return "user:test";
    }
    
    @RequestMapping("/home/admin")
    @RequiresPermissions("user:admin")
    public String admin(){
        return "user:admin";
    }
    
    @RequestMapping("/login")
    public String login(String username, String password){
        Subject subject = SecurityUtils.getSubject();
        try{
            //登录，会调用UserRealm#doGetAuthenticationInfo()，判断使用账号密码正确
            subject.login(new UsernamePasswordToken(username, password));
            
            //登录成功，获取token
            Session session = subject.getSession();
            
            return "token: " + session.getId();
        }
        catch(AuthenticationException exception){
            //登录失败，报错
            return "用户名或密码错误";
        }
    }
}
