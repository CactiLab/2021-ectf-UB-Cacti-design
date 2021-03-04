# 2021 Collegiate eCTF
# Generate SED secrets Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

# load current SSS container to modify
ARG DEPLOYMENT
FROM ${DEPLOYMENT}/sss

ARG SCEWL_ID

# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
# NOTE: to maximize the useage of container cache, use ADD to map in only the files/directories you need
#       (e.g. only mapping in the SED directory rather than the entire repo)

# do here whatever you need here to create secrets for the new SED that the SSS needs access to

##############################
RUN mkdir /secrets/${SCEWL_ID}
RUN echo ${SCEWL_ID} >> /provisoned_list

##############################
# generate rsa key files for SCEWL_ID
WORKDIR /secrets/rsa
RUN ./keygen
RUN mv privateKey.txt publicKey.txt /secrets/${SCEWL_ID}
RUN cp publicKey /${SCEWL_ID}_publicKey
# RUN make clean

##############################
# Read key files from the sss/$SCEWL_ID/ to generate the key.h file
WORKDIR /secrets
RUN python3 create_secret ${SCEWL_ID} generate_key

##############################