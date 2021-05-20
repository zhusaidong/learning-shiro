package com.example.shiro.config;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.session.mgt.eis.AbstractSessionDAO;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.context.annotation.Configuration;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * @author zhusaidong
 */
@Configuration
public class ShiroConfiguration implements ShiroConfig{
    /**
     * 模拟数据库：用户
     */
    private static final Map<String, String> DB_USER = new HashMap<>();
    /**
     * 模拟数据库：盐值
     */
    private static final Map<String, String> DB_USER_SALT = new HashMap<>();
    /**
     * 模拟数据库：权限
     */
    private static final Map<String, List<String>> DB_USER_PERMISSIONS = new HashMap<>();
    
    static{
        DB_USER_SALT.put("admin", "qwert");
        DB_USER_SALT.put("test", "asdfg");
        
        DB_USER.put("admin", new Md5Hash(new Md5Hash("admin"), DB_USER_SALT.get("admin")).toHex());
        DB_USER.put("test", new Md5Hash(new Md5Hash("test"), DB_USER_SALT.get("test")).toHex());
        
        DB_USER_PERMISSIONS.put("admin", Collections.singletonList("user:admin"));
        DB_USER_PERMISSIONS.put("test", Collections.singletonList("user:test"));
    }
    
    @Override
    public Object noAuthenticationException(){
        return "需要登录";
    }
    
    @Override
    public Object noAuthorizationException(){
        return "没有权限";
    }
    
    @Override
    public AbstractSessionDAO sessionDAO(){
        return new MemorySessionDAO();
    }
    
    @Override
    public String encryptedPassword(String inputPassword, String salt){
        //md5(md5(password) + salt)
        return new Md5Hash(new Md5Hash(inputPassword), salt).toHex();
    }
    
    @Override
    public List<String> routesWithoutAuthentication(){
        return Collections.singletonList("/login");
    }
    
    @Override
    public String getSessionId(HttpServletRequest httpServletRequest){
        return httpServletRequest.getHeader("token");
    }
    
    @Override
    public void doGetAuthorizationInfo(PrincipalCollection principalCollection, SimpleAuthorizationInfo authorizationInfo){
        //登录鉴权方法doGetAuthenticationInfo()返回的SimpleAuthenticationInfo中第一个参数，可以是User对象也可以是uid
        String username = (String)principalCollection.getPrimaryPrincipal();
        
        //获取当前用户的权限
        authorizationInfo
                .setStringPermissions(new HashSet<>(DB_USER_PERMISSIONS.getOrDefault(username, new ArrayList<>())));
    }
    
    @Override
    public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException{
        String username = (String)authenticationToken.getPrincipal();
        
        //查询数据库，根据用户名查询出密码传入SimpleAuthenticationInfo，shiro会匹配
        if(!DB_USER.containsKey(username)){
            throw new UnknownAccountException("用户不存在");
        }
        
        String password = DB_USER.get(username);
        String salt     = DB_USER_SALT.get(username);
        
        return new SimpleAuthenticationInfo(username, password, ByteSource.Util.bytes(salt), username);
    }
}
