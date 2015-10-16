<p align="center">
  <img src="https://pac4j.github.io/pac4j/img/logo-spring-webmvc.png" width="300" />
</p>

This `spring-webmvc-pac4j-boot-demo` project is a Spring Boot application to test the [spring-webmvc-pac4j](https://github.com/pac4j/spring-webmvc-pac4j) security library with various authentication mechanisms: Facebook, Twitter, form, basic auth, CAS, SAML, OpenID Connect, JWT...

## Start & test

Build the project and launch the web app with jetty on [http://localhost:8080](http://localhost:8080):

    cd spring-webmvc-pac4j-boot-demo
    mvn clean compile exec:java

To test, you can call a protected url by clicking on the "Protected url by **xxx**" link, which will start the authentication process with the **xxx** provider.  
Or you can click on the "Authenticate with **xxx**" link to manually start the authentication process with the **xxx** provider.

To test the CAS support, you need to start a CAS server on port 8888. Use the following demo: [cas-overlay-demo](https://github.com/leleuj/cas-overlay-demo) with the option: `-Djetty.port=8888`.
