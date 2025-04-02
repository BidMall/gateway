FROM openjdk:21-jdk-slim
COPY build/libs/gateway-0.0.1-SNAPSHOT.jar gateway.jar
ENV TZ=Asia/Seoul
ENTRYPOINT ["java", "-jar", "gateway.jar"]
