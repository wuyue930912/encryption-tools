package com.may.core;

import com.may.core.service.EncryptionService;
import com.may.core.service.impl.EncryptionServiceImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(EncryptionToolProperties.class)
public class EncryptionToolAutoConfiguration {

    private final EncryptionToolProperties properties;

    public EncryptionToolAutoConfiguration(EncryptionToolProperties properties) {
        this.properties = properties;
    }

    @Bean
    @ConditionalOnMissingBean(EncryptionService.class)
    public EncryptionService encryptionService() {
        return new EncryptionServiceImpl(properties);
    }

}
