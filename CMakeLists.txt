set(source_files
    model/zt-certificate.cc
    model/zt-encryption-utils.cc
    model/zt-policy-engine.cc
    model/zt-logger.cc
    model/zt-tls-handshake.cc
)

set(header_files
    model/zt-certificate.h
    model/zt-encryption-utils.h
    model/zt-policy-engine.h
    model/zt-logger.h
    model/zt-tls-handshake.h
)

build_lib(
  LIBNAME zero-trust-iot
  SOURCE_FILES ${source_files}
  HEADER_FILES ${header_files}
  LIBRARIES_TO_LINK ${libcore} ${libnetwork} ${libinternet} ${libwifi}
)

