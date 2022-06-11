package com.example.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.userdetails.PersonContextMapper;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
            .antMatchers("/user", "/user.*", "/user/**").hasRole("USER") // userグループ用
            .antMatchers("/admin", "/admin.*", "/admin/**").hasRole("ADMIN") // adminグループ用
            .antMatchers("/**").authenticated()
            .and()
            .logout().permitAll()
            .and()
            .formLogin().permitAll();
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.ldapAuthentication()
                // ユーザーの識別名(DN=Distinguished Name)パターンを指定
                // {0}にはログインフォームで入力したusernameが埋め込まれる
                .userDnPatterns("uid={0},ou=people")
                // グループ（ロール）を検索するユニットを指定
                .groupSearchBase("ou=groups")
                // LDAPのデータソースを指定
                .contextSource()
                    // 接続URLを指定
                    .url("ldap://localhost:10389/dc=example,dc=com")
                    // LDAPに接続するためのユーザーの識別名を指定
                    .managerDn("cn=admin,dc=example,dc=com") 
                    // LDAPに接続するためのパスワードを指定
                    .managerPassword("password")
                .and()
                // UserDetailsを生成するオブジェクトを指定
                // デフォルトはLdapUserDetailsMapperが利用されるが、本エントリーでは氏名(cn=Common Name)が参照できるPersonContextMapperを利用
                // → 要件にあった実装を選択する or 実装する
                .userDetailsContextMapper(new PersonContextMapper());
	}

}
