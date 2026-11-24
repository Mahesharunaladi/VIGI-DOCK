FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml ./
COPY BACKEND/pom.xml BACKEND/pom.xml
RUN mvn -B -pl BACKEND -am dependency:go-offline
COPY BACKEND/src BACKEND/src
RUN mvn -B -pl BACKEND -am clean package -DskipTests

FROM eclipse-temurin:17-jre-jammy
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg python3 python3-pip apt-transport-https && \
    install -d -m 0755 /etc/apt/keyrings && \
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /etc/apt/keyrings/google-cloud.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/google-cloud.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y --no-install-recommends google-cloud-cli kubectl google-cloud-cli-gke-gcloud-auth-plugin trivy ansible && \
    pip3 install --no-cache-dir kubernetes PyYAML && ansible-galaxy collection install kubernetes.core && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1001 vigidock && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin vigidock
ENV TRIVY_CACHE_DIR=/home/vigidock/.cache/trivy
RUN mkdir -p "$TRIVY_CACHE_DIR" && trivy --cache-dir "$TRIVY_CACHE_DIR" image --download-db-only && chown -R vigidock:vigidock /home/vigidock/.cache
WORKDIR /app
COPY --from=build /workspace/BACKEND/target/vigidock-backend-1.0.0-SNAPSHOT.jar /app/app.jar
COPY BACKEND/src/main/resources/ansible /app/ansible
RUN chown -R vigidock:vigidock /app
USER 1001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
