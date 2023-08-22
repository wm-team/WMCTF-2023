FROM openjdk:8-jre-alpine

# copy jar from the first stage
RUN mkdir /app/
COPY ./app.jar /app/app.jar
COPY ./flag /flag
WORKDIR /app/

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]