package kr.sbomsight.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** MVC 인터셉터 등록. */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final MustChangePasswordInterceptor mustChangePassword;

    public WebConfig(MustChangePasswordInterceptor mustChangePassword) {
        this.mustChangePassword = mustChangePassword;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(mustChangePassword).addPathPatterns("/**");
    }
}
