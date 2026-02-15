.PHONY: build clean test

build:
	mvn -q package -DskipTests

clean:
	mvn -q clean

test: build
	@echo "Run manually: java -jar target/service-b-1.0-SNAPSHOT.jar"
