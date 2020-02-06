package tacos.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http.authorizeRequests()
                .antMatchers("/design", "/orders")
                    .access("hasRole('ROLE_USER')")
                .antMatchers("/", "/**").access("permitAll()")
            .and()
                .formLogin()
                    .loginPage("/login")
                    .defaultSuccessUrl("/design", true)
            .and()
                .logout()
                    .logoutSuccessUrl("/");
    }

    //Basic
//    @Override
//    protected void configure(HttpSecurity http) throws Exception{
//        http.authorizeRequests()
//                .antMatchers("/design", "/orders")
//                    .hasRole("ROLE_USER")
//                .antMatchers("/", "/**").permitAll();
//    }

    //SpEL
//    @Override
//    protected void configure(HttpSecurity http) throws Exception{
//        http.authorizeRequests()
//                .antMatchers("/design", "/orders")
//                    .access("hasRole('ROLE_USER') && " +
//                        "T(java.util.Calendar).getInstance().get(" +
//                        "T(java.util.Calendar).DAY_OF_WEEK) == " +
//                        "T(java.util.Calendar).TUESDAY")
//                .antMatchers("/", "/**").access("permitAll()");
//    }

    @Bean
    public PasswordEncoder encoder(){
        return new StandardPasswordEncoder("53cr3t");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.userDetailsService(userDetailsService)
            .passwordEncoder(encoder());
    }


    //Basic configuration
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
//        auth.inMemoryAuthentication()
//                .withUser("buzz")
//                .password("infinity")
//                .authorities("ROLE_USER")
//                .and()
//                .withUser("woody")
//                .password("bullseye")
//                .authorities("ROLE_USER");
//    }

    //JDBC configuration
//    @Autowired
//    DataSource dataSource;
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//        .usersByUsernameQuery(
//                "select username, password, enabled from Users"+
//                "where username=?")
//        .authoritiesByUsernameQuery(
//                "select username, authority from UserAuthorities"+
//                "where username=?")
//        .passwordEncoder(new StandardPasswordEncoder("53cr3t"));
//    }

    //LDAP configuration
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
//        auth.ldapAuthentication()
//                .userSearchBase("ou=people")
//                .userSearchFilter("(uid={0})")
//                .groupSearchBase("ou=groups")
//                .groupSearchFilter("member={0}")
//                .passwordCompare()
//                .passwordEncoder(new BCryptPasswordEncoder())
//                .passwordAttribute("passcode")
//                .contextSource() //not recognized method
//                    .url("ldap://tacocloud.com:389/dc=tacocloud.dc=com");
//                        //or if there is no LDAP server
//                        //.root("dc=tacocloud.dc=com").ldif("classpath:users.ldif");
//    }
}
