FROM maven:3.9.2-eclipse-temurin-17-alpine AS build

COPY ./pom.xml /pom.xml
COPY ./src ./src

RUN mvn -e --no-transfer-progress clean install -am -DskipTests

FROM eclipse-temurin:17.0.7_7-jre-alpine

COPY --from=build /target/admin-panel-*.jar /admin-panel.jar

ENTRYPOINT java -jar admin-panel.jar