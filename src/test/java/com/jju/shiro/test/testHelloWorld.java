package com.jju.shiro.test;



import java.util.Arrays;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;
import org.junit.Test;

public class testHelloWorld {

	@Test
	public void test() {
		//获取SecurityManager工厂，，此处使用Ini配置文件初始化
		IniSecurityManagerFactory factory = new  IniSecurityManagerFactory("classpath:shiro-jdbc-realm.ini");
		//得到SecurityManager实例，并绑定SecurityUtils
		SecurityManager securityManager = factory.getInstance();
		SecurityUtils.setSecurityManager(securityManager);
		//得到Subject并且创建用户名密码身份验证Token
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken userToken = new UsernamePasswordToken("zhang","123");
		
		try {
			//登陆，即进行身份验证
			subject.login(userToken);
		} catch (AuthenticationException e) {
			//身份验证失败
			System.out.println("用户名或密码错误");
			throw new AuthenticationException();
		}
		//断言用户已经登陆
		Assert.assertEquals(true, subject.isAuthenticated());
		//退出
		subject.logout();
	}
	public void login(String configFile, String username, String password) {
		//1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory =new IniSecurityManagerFactory(configFile);
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        subject.login(token);
	}
	
	private Subject subject() {
        Subject subject = SecurityUtils.getSubject();
		return subject;
	}

	
	@Test
	public void testHasRole(){
		login("classpath:shiro-role.ini","zhang","123");
		//判断拥有角色：role1
		Assert.assertTrue(subject().hasRole("role1"));
		//判断拥有角色：role1 and role2
		Assert.assertTrue(subject().hasAllRoles(Arrays.asList("roleq","role2")));
		 //判断拥有角色：role1 and role2 and !role3
        boolean[] result = subject().hasRoles(Arrays.asList("role1", "role2", "role3"));
        Assert.assertEquals(true, result[0]);
        Assert.assertEquals(true, result[1]);
        Assert.assertEquals(false, result[2]);
	}
	
	@Test(expected = UnauthorizedException.class)
    public void testCheckRole() {
        login("classpath:shiro-role.ini", "zhang", "123");
        //断言拥有角色：role1
        subject().checkRole("role1");
        //断言拥有角色：role1 and role3 失败抛出异常
        subject().checkRoles("role1", "role3");
    }
	
	@Test
    public void testIsPermitted() {
        login("classpath:shiro-permission.ini", "zhang", "123");
        //判断拥有权限：user:create
        Assert.assertTrue(subject().isPermitted("user:create"));
        //判断拥有权限：user:update and user:delete
        Assert.assertTrue(subject().isPermittedAll("user:update", "user:delete"));
        //判断没有权限：user:view
        Assert.assertFalse(subject().isPermitted("user:view"));
    }
	
	
    @Test(expected = UnauthorizedException.class)
    public void testCheckPermission () {
        login("classpath:shiro-permission.ini", "zhang", "123");
        //断言拥有权限：user:create
        subject().checkPermission("user:create");
        //断言拥有权限：user:delete and user:update
        subject().checkPermissions("user:delete", "user:update");
        //断言拥有权限：user:view 失败抛出异常
        subject().checkPermissions("user:view");
    }
}
