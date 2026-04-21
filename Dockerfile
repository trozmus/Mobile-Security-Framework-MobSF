# Base image
FROM python:3.13-slim-bookworm

LABEL \
    name="MobSF" \
    author="Ajin Abraham <ajin25@gmail.com>" \
    maintainer="Ajin Abraham <ajin25@gmail.com>" \
    contributor_1="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    contributor_2="Vincent Nadal <vincent.nadal@orange.fr>" \
    description="Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis."

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    MOBSF_PLATFORM=docker \
    MOBSF_ADB_BINARY=/usr/bin/adb \
    JAVA_HOME=/jdk-22.0.2 \
    PATH=/jdk-22.0.2/bin:/root/.local/bin:$PATH \
    DJANGO_SUPERUSER_USERNAME=mobsf \
    DJANGO_SUPERUSER_PASSWORD=mobsf \
    MOBSF_USER=mobsf \
    USER_ID=9901 \
    MOBSF_HOME=/home/mobsf/.MobSF

RUN apt update -y && \
    apt install -y --no-install-recommends \
        android-sdk-build-tools \
        android-tools-adb \
        build-essential \
        ca-certificates \
        curl \
        fontconfig \
        fontconfig-config \
        git \
        libfontconfig1 \
        libjpeg62-turbo \
        libxext6 \
        libxrender1 \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        libxml2-dev \
        locales \
        pkg-config \
        procps \
        python3-dev \
        sqlite3 \
        supervisor \
        unzip \
        wget \
        xfonts-75dpi \
        xfonts-base && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt upgrade -y && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    apt autoremove -y && apt clean -y && rm -rf /var/lib/apt/lists/* /tmp/*

ARG TARGETPLATFORM

# Install wkhtmltopdf, OpenJDK and jadx
COPY scripts/dependencies.sh mobsf/MobSF/tools_download.py ./
RUN ./dependencies.sh

# Install Python dependencies
COPY pyproject.toml .
RUN poetry config virtualenvs.create false && \
    poetry lock && \
    poetry install --only main --no-root --no-interaction --no-ansi && \
    poetry cache clear . --all --no-interaction && \
    rm -rf /root/.cache/

# Install Rust (needed for bcrypt compilation from source)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal

# Copy supervisord config
COPY docker/supervisord.conf /etc/supervisor/conf.d/mobsf.conf

# Copy source code
WORKDIR /home/mobsf/Mobile-Security-Framework-MobSF
COPY . .

RUN chmod +x scripts/entrypoint_queue.sh

EXPOSE 8000 1337

RUN groupadd --gid $USER_ID $MOBSF_USER && \
    useradd $MOBSF_USER --uid $USER_ID --gid $MOBSF_USER --shell /bin/false && \
    mkdir -p /home/mobsf/.MobSF && \
    chown -R $MOBSF_USER:$MOBSF_USER /home/mobsf

VOLUME /home/mobsf/.MobSF

USER $MOBSF_USER

CMD ["/home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint_queue.sh"]
