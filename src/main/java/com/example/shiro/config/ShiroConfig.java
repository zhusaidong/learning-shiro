package com.example.shiro.config;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.mgt.eis.AbstractSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * @author zhusaidong
 */
public interface ShiroConfig{
    /**
     * Shiro控制器
     */
    @RestController
    @RequestMapping("/shiro")
    class ShiroController{
        @Autowired
        private ShiroConfig shiroConfig;
        
        @RequestMapping("/needAuthentication")
        public Object needAuthentication(){
            return shiroConfig.noAuthenticationException();
        }
        
        @RequestMapping("/needAuthorization")
        public Object needAuthorization(){
            return shiroConfig.noAuthorizationException();
        }
    }
    
    /**
     * session id生成器
     *
     * @return session id生成器
     */
    default SessionIdGenerator sessionIdGenerator(){
        return session -> UUID.randomUUID().toString().replace("-", "");
    }
    
    /**
     * Filter工厂,设置url权限
     *
     * @return filter
     */
    @Bean
    default ShiroFilterFactoryBean shiroFilterFactoryBean(){
        ShiroFilterFactoryBean shiroFilter = new ShiroFilterFactoryBean();
        shiroFilter.setSecurityManager(securityManager());
        shiroFilter.setLoginUrl("/shiro/needAuthentication");
        
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        //anon:所有url都可以匿名访问
        routesWithoutAuthentication().forEach(route -> filterChainDefinitionMap.put(route, "anon"));
        
        filterChainDefinitionMap.put("/shiro/needAuthentication", "anon");
        filterChainDefinitionMap.put("/shiro/needAuthorization", "anon");
        filterChainDefinitionMap.put("/static/**", "anon");
        //authc:所有url都必须认证通过才可以访问
        //主要这行代码必须放在所有权限设置的最后，不然会导致所有 url 都被拦截 剩余的都需要认证
        filterChainDefinitionMap.put("/**", "authc");
        
        shiroFilter.setFilterChainDefinitionMap(filterChainDefinitionMap);
        
        return shiroFilter;
    }
    
    /**
     * shiro异常处理器
     *
     * @return 异常处理器
     */
    @Bean
    default SimpleMappingExceptionResolver simpleMappingExceptionResolver(){
        SimpleMappingExceptionResolver resolver   = new SimpleMappingExceptionResolver();
        Properties                     properties = new Properties();
        properties.setProperty("org.apache.shiro.authz.UnauthorizedException", "/shiro/needAuthorization");
        resolver.setExceptionMappings(properties);
        return resolver;
    }
    
    /**
     * 加密规则匹配器
     *
     * @return 加密规则匹配器
     */
    default CredentialsMatcher credentialsMatcher(){
        return (authenticationToken, authenticationInfo) -> {
            //用户输入的密码
            String inputPassword;
            if(authenticationToken instanceof UsernamePasswordToken){
                inputPassword = new String(((UsernamePasswordToken)authenticationToken).getPassword());
            }else{
                inputPassword = (String)authenticationToken.getCredentials();
            }
            
            //数据库查询出的密码
            SimpleAuthenticationInfo simpleAuthenticationInfo = (SimpleAuthenticationInfo)authenticationInfo;
            
            String dbPassword = (String)simpleAuthenticationInfo.getCredentials();
            String salt       = new String(simpleAuthenticationInfo.getCredentialsSalt().getBytes());
            
            return encryptedPassword(inputPassword, salt).equals(dbPassword);
        };
    }
    
    /**
     * session管理器
     *
     * @return session管理器
     */
    default WebSessionManager sessionManager(){
        DefaultWebSessionManager webSessionManager = new DefaultWebSessionManager(){
            @Override
            protected Serializable getSessionId(ServletRequest request, ServletResponse response){
                super.getSessionId(request, response);
                return ShiroConfig.this.getSessionId((HttpServletRequest)request);
            }
        };
        AbstractSessionDAO sessionDAO = sessionDAO();
        sessionDAO.setSessionIdGenerator(sessionIdGenerator());
        webSessionManager.setSessionDAO(sessionDAO);
        webSessionManager.setSessionIdUrlRewritingEnabled(false);
        
        return webSessionManager;
    }
    
    /**
     * 安全管理器
     *
     * @return 安全管理器
     */
    @Bean
    default DefaultWebSecurityManager securityManager(){
        DefaultWebSecurityManager webSecurityManager = new DefaultWebSecurityManager();
        
        AuthorizingRealm realm = userRealm();
        realm.setCredentialsMatcher(credentialsMatcher());
        webSecurityManager.setRealm(realm);
        webSecurityManager.setSessionManager(sessionManager());
        
        return webSecurityManager;
    }
    
    /**
     * 用户的授权/鉴权
     *
     * @return 用户的授权/鉴权
     */
    @Bean
    default AuthorizingRealm userRealm(){
        return new AuthorizingRealm(){
            /**
             * 授权, 即登录过后，校验是否有权限.
             */
            @Override
            protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection){
                SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
                ShiroConfig.this.doGetAuthorizationInfo(principalCollection, authorizationInfo);
                return authorizationInfo;
            }
            
            /**
             * 鉴权, 登录时通过账号和密码验证登陆人的身份信息
             */
            @Override
            protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException{
                return ShiroConfig.this.doGetAuthenticationInfo(authenticationToken);
            }
        };
    }
    
    /**
     * 未登录异常信息
     *
     * @return 异常信息
     */
    Object noAuthenticationException();
    
    /**
     * 无权限异常信息
     *
     * @return 异常信息
     */
    Object noAuthorizationException();
    
    /**
     * 自定义session存储器，比如用redis存储
     *
     * @return session存储器
     */
    AbstractSessionDAO sessionDAO();
    
    /**
     * 加密方法
     *
     * @param inputPassword 输入密码
     * @param salt          盐值
     *
     * @return 加密的密码
     */
    String encryptedPassword(String inputPassword, String salt);
    
    /**
     * 无需鉴权的路由
     *
     * @return 路由
     */
    List<String> routesWithoutAuthentication();
    
    /**
     * 获取session id
     *
     * @param httpServletRequest http request
     *
     * @return session id
     */
    String getSessionId(HttpServletRequest httpServletRequest);
    
    /**
     * 授权, 即登录过后，校验是否有权限.
     *
     * @param principalCollection principal集合
     * @param authorizationInfo   授权信息
     */
    void doGetAuthorizationInfo(PrincipalCollection principalCollection, SimpleAuthorizationInfo authorizationInfo);
    
    /**
     * 鉴权, 登录时通过账号和密码验证登陆人的身份信息
     *
     * @param authenticationToken authentication token
     *
     * @return authentication 信息
     *
     * @throws AuthenticationException authentication异常
     */
    AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException;
}
