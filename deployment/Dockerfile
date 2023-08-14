FROM maven:3.9.2-eclipse-temurin-17-alpine AS build

COPY ./pom.xml /pom.xml
COPY ./src ./src

RUN mvn -e --no-transfer-progress clean install -am -DskipTests

FROM eclipse-temurin:17.0.7_7-jre-alpine

COPY --from=build /target/admin-panel-*.jar /admin-panel.jar

RUN apk update --quiet && \
    apk add --no-cache \
            --quiet \
            openssl

RUN openssl s_client -showcerts -connect seart-ghs.si.usi.ch:443 </dev/null 2>/dev/null | \
    openssl x509 -outform PEM > /tmp/seart-ghs.si.usi.ch.pem

RUN keytool \
    -import \
    -alias seart-ghs.si.usi.ch \
    -file /tmp/seart-ghs.si.usi.ch.pem \
    -keystore $JAVA_HOME/lib/security/cacerts \
    -storepass changeit \
    -noprompt

RUN openssl s_client -showcerts -connect seart-dl4se.si.usi.ch:443 </dev/null 2>/dev/null | \
    openssl x509 -outform PEM > /tmp/seart-dl4se.si.usi.ch.pem

RUN keytool \
    -import \
    -alias seart-dl4se.si.usi.ch \
    -file /tmp/seart-dl4se.si.usi.ch.pem \
    -keystore $JAVA_HOME/lib/security/cacerts \
    -storepass changeit \
    -noprompt

ENTRYPOINT java -jar admin-panel.jar