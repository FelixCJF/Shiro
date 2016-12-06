package com.jju.shiro.test;



import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.Subject;
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

}
