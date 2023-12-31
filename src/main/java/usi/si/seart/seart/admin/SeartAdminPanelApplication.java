package usi.si.seart.seart.admin;

import de.codecentric.boot.admin.server.config.EnableAdminServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableAdminServer
@SpringBootApplication
public class SeartAdminPanelApplication {

    public static void main(String[] args) {
        SpringApplication.run(SeartAdminPanelApplication.class, args);
    }
}
