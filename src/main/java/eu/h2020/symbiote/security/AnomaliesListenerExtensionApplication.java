package eu.h2020.symbiote.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication(scanBasePackages = "eu.h2020.symbiote.security")
public class AnomaliesListenerExtensionApplication {

	public static void main(String[] args) {
		SpringApplication.run(AnomaliesListenerExtensionApplication.class, args);
	}
}
