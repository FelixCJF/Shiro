package com.jju.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.Realm;

public class MyRealm1 implements Realm {

	//根据Token获取认证信息
	@Override
	public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token)
			throws AuthenticationException {
		String username = (String) token.getPrincipal();//得到用户名
		String password = (String) token.getCredentials();//得到密码
		if (!"zhang".equals(username)) {
			throw new UnknownAccountException();//用户名异常
		}
		if (!"1234".equals(password)) {
			throw new IncorrectCredentialsException();//密码错误
		}
		//如果身份验证成功，返回一个AuthenticationInfo实现
		return new SimpleAuthenticationInfo(username, password, getName());
	}

	@Override
	public String getName() {
		return "myrealm1";
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		//仅支持UsernamePasswordToken类型的Token
		return token instanceof UsernamePasswordToken;
	}

}
