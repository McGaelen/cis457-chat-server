build:
	javac proj3/Client.java
	javac proj3/Server.java

run-server:
	java proj3.Server 9876

run-client:
	java proj3.Client 9876 127.0.0.1
