# 2021 Collegiate eCTF
# Remove SED Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

# load current SSS container to modify
# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
ARG DEPLOYMENT
FROM ${DEPLOYMENT}/sss

ARG SCEWL_ID

# do whatever you need to remove the SED from the deployment

##############################
# This test is done
RUN python3 create_secret ${SCEWL_ID}  delete_key && \
    grep -w -n ${SCEWL_ID} /provisoned_list | cut -f1 -d ":" | xargs -I % sed -i '%d' /provisoned_list  && \
    rm -rf ${SCEWL_ID}

##############################