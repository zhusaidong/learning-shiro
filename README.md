# 学习shiro

shiro比较简单。shiro学会后再学Spring Security。

## 配置

创建一个拦截器`ShiroFilterFactoryBean`

配置url是否需要权限。

## realm

提供用户具体鉴权/授权的方法

`doGetAuthorizationInfo` 授权, 即登录后，调用权限判断时，判断登录用户应有的权限。结合`@RequiresPermissions`做权限判断。

`doGetAuthenticationInfo` 鉴权, 登录时通过账号和密码验证身份信息。

## sessionManager

session的管理方法，可以设置内存/redis存放等

## 权限

`@RequiresPermissions("user:admin")` 设置权限。颗粒度最小，每个方法可以设置不同权限。

`@RequiresRoles("admin")` 设置角色。颗粒度比较大，一个系统中角色有限，做不到每个方法一个角色。

`@RequiresAuthentication` 判断是否登录。颗粒度最大，只要登录即可访问。

## 登录

控制器的登录方法，调用`subject.login()`做登录，shiro会调用UserRealm#doGetAuthenticationInfo()，验证账号密码。

验证成功通过`SessionManager`管理session，`SessionManager`使用`SessionDAO`保存session。

## Subject

用户主体。包含用户信息/权限/角色等。实现原理为`ThreadLocal`

