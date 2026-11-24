# Honeypot Dionaea (capture de charges malveillantes) sur l'adresse leurre 192.168.10.50
# VM d'origine : Dionaea 0.11.0 compilé depuis Git ; ici l'image officielle 0.11.0.
FROM dinotools/dionaea:0.11.0

# Arborescence par défaut de l'image, puis configuration de la VM par-dessus
RUN cd /opt/dionaea && cp -a template/etc . && cp -a template/lib var/ && cp -a template/log var/ \
    && rm -f etc/dionaea/services-enabled/* etc/dionaea/ihandlers-enabled/*
COPY dionaea.cfg /opt/dionaea/etc/dionaea/dionaea.cfg
COPY services-enabled/ /opt/dionaea/etc/dionaea/services-enabled/
COPY ihandlers-enabled/ /opt/dionaea/etc/dionaea/ihandlers-enabled/
RUN chown -R dionaea:dionaea /opt/dionaea/var

WORKDIR /opt/dionaea
# Équivalent de dionaea.service (la VM l'exécutait en root ; ici l'utilisateur dédié de l'image)
ENTRYPOINT ["/opt/dionaea/bin/dionaea", "-u", "dionaea", "-g", "dionaea", "-w", "/opt/dionaea", \
            "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg", "-l", "warning,error"]
