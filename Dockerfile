# Install swagger codegen

FROM maven:3-jdk-8-alpine AS SERVER_GEN
RUN wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.20/swagger-codegen-cli-3.0.20.jar -O swagger-codegen-cli.jar

# Generate CNWAN adaptor

COPY adaptor_server/adaptor_api.yaml .
COPY adaptor_server/generator_config.json .

RUN java -jar swagger-codegen-cli.jar generate \
  -i adaptor_api.yaml \
  -l python-flask \
  -o adaptor_server \
  -c generator_config.json

# Python server setup
FROM python:3.6-alpine

# Build adaptor Python library
COPY adaptor_library adaptor_library
WORKDIR adaptor_library
RUN python3 setup.py sdist bdist_wheel


# Copy server files
WORKDIR /
RUN mkdir -p /usr/src/app
COPY --from=SERVER_GEN adaptor_server /usr/src/app
RUN cp adaptor_library/dist/metadata_adaptor-2.0.0.tar.gz .
COPY adaptor_server/configure_controller.py usr/src/app/cnwan_adaptor/controllers
COPY adaptor_server/requirements.txt .

# Install dependencies
RUN pip3 install --no-cache-dir -r requirements.txt
RUN pip3 install metadata_adaptor-2.0.0.tar.gz


# Run server
WORKDIR /usr/src/app

EXPOSE 8080

ENTRYPOINT ["python3"]

CMD ["-m", "cnwan_adaptor"]
