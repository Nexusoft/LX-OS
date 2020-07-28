#ifndef AAS_SEND_H
#define AAS_SEND_H

#define TRUDOC_SERVER_PORT 5944
#define TRUDOC_HELLO "hello trudoc"

#define ODF_NFILES 5
#define ODF_NREQUIREDFILES 4
#define ODF_FILES { \
  "content.canonical.xml", \
  "styles.canonical.xml", \
  "meta.canonical.xml", \
  "settings.canonical.xml", \
  "META-INF/documentsignatures.canonical.xml" }

#endif // AAS_SEND_H
