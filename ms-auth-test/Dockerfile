FROM eclipse-temurin:21-jdk-jammy
WORKDIR /app
COPY target/ms-auth-test-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8095
ENTRYPOINT ["java", "-jar", "app.jar"]
