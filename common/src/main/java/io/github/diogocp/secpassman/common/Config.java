package io.github.diogocp.secpassman.common;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {
    private String host;
    private String port;

    public Config(){
        this.getPropertyValues();
    }

    public String getHost() { return host;}
    public String getPort() { return port; }


    public void getPropertyValues(){

        Properties prop = new Properties();
        InputStream input = null;
        String filename = "config.properties";

        try {

            input = getClass().getClassLoader().getResourceAsStream(filename);

            // load a properties file
            prop.load(input);

            host = prop.getProperty("host");
            port = prop.getProperty("port");

        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }
}
