# Copyright (c) 2021, Oracle Corporation and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

# Description: to create Azure Application Gateway ingress for the following targets.
#   * [Optional] Admin console, with path host/console
#   * [Optional] Admin remote console, with path host/remoteconsole
#   * Cluster, with path host/*

echo "Script  ${0} starts"

# read <spBase64String> <appgwFrontendSSLCertPsw> from stdin
function read_sensitive_parameters_from_stdin() {
  read spBase64String appgwFrontendSSLCertPsw
}

function generate_appgw_cluster_config_file_nossl() {
    clusterIngressName=${wlsDomainUID}-cluster-appgw-ingress-svc
    clusterAppgwIngressYamlPath=${scriptDir}/appgw-cluster-ingress-svc.yaml
    cat <<EOF >${clusterAppgwIngressYamlPath}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${clusterIngressName}
  namespace: ${wlsDomainNS}
  annotations:
    kubernetes.io/ingress.class: azure/application-gateway
EOF

    if [[ "${enableCookieBasedAffinity,,}" == "true" ]]; then
        cat <<EOF >>${clusterAppgwIngressYamlPath}
    appgw.ingress.kubernetes.io/cookie-based-affinity: "true"
EOF
    fi

    cat <<EOF >>${clusterAppgwIngressYamlPath}
spec:
  rules:
    - http:
        paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: ${svcCluster}
              port:
                number: ${clusterTargetPort}
EOF
}

# Create network peers for aks and appgw
function network_peers_aks_appgw() {
    # To successfully peer two virtual networks command 'az network vnet peering create' must be called twice with the values
    # for --vnet-name and --remote-vnet reversed.
    aksMCRGName=$(az aks show -n $aksClusterName -g $aksClusterRGName -o tsv --query "nodeResourceGroup")
    ret=$(az group exists -n ${aksMCRGName})
    if [ "${ret,,}" == "false" ]; then
        echo_stderr "AKS namaged resource group ${aksMCRGName} does not exist."
        exit 1
    fi

    aksNetWorkId=$(az resource list -g ${aksMCRGName} --resource-type Microsoft.Network/virtualNetworks -o tsv --query '[*].id')
    aksNetworkName=$(az resource list -g ${aksMCRGName} --resource-type Microsoft.Network/virtualNetworks -o tsv --query '[*].name')
    az network vnet peering create \
        --name aks-appgw-peer \
        --remote-vnet ${aksNetWorkId} \
        --resource-group ${curRGName} \
        --vnet-name ${vnetName} \
        --allow-vnet-access
    utility_validate_status "Create network peers for $aksNetWorkId and ${vnetName}."

    appgwNetworkId=$(az resource list -g ${curRGName} --name ${vnetName} -o tsv --query '[*].id')
    az network vnet peering create \
        --name aks-appgw-peer \
        --remote-vnet ${appgwNetworkId} \
        --resource-group ${aksMCRGName} \
        --vnet-name ${aksNetworkName} \
        --allow-vnet-access

    utility_validate_status "Create network peers for $aksNetWorkId and ${vnetName}."

    # For Kbectl network plugin: https://azure.github.io/application-gateway-kubernetes-ingress/how-tos/networking/#with-kubenet
    # find route table used by aks cluster
    routeTableId=$(az network route-table list -g $aksMCRGName --query "[].id | [0]" -o tsv)

    # get the application gateway's subnet
    appGatewaySubnetId=$(az network application-gateway show -n $appgwName -g $curRGName -o tsv --query "gatewayIpConfigurations[0].subnet.id")

    # associate the route table to Application Gateway's subnet
    az network vnet subnet update \
        --ids $appGatewaySubnetId \
        --route-table $routeTableId

    utility_validate_status "Associate the route table ${routeTableId} to Application Gateway's subnet ${appGatewaySubnetId}"
}

function query_cluster_target_port() {
    if [[ "${enableCustomSSL,,}" == "true" ]]; then
        clusterTargetPort=$(utility_query_service_port ${svcCluster} ${wlsDomainNS} 'default-secure')
    else
        clusterTargetPort=$(utility_query_service_port ${svcCluster} ${wlsDomainNS} 'default')
    fi

    echo "Cluster port of ${clusterName}: ${clusterTargetPort}"
}

function install_azure_ingress() {
    # create sa and bind cluster-admin role
    # grant azure ingress permission to access WebLogic service
    kubectl apply -f ${scriptDir}/appgw-ingress-clusterAdmin-roleBinding.yaml

    install_helm
    helm repo add application-gateway-kubernetes-ingress ${appgwIngressHelmRepo}
    helm repo update

    # generate Helm config for azure ingress
    customAppgwHelmConfig=${scriptDir}/appgw-helm-config.yaml
    cp ${scriptDir}/appgw-helm-config.yaml.template ${customAppgwHelmConfig}
    subID=${subID#*\/subscriptions\/}
    sed -i -e "s:@SUB_ID@:${subID}:g" ${customAppgwHelmConfig}
    sed -i -e "s:@APPGW_RG_NAME@:${curRGName}:g" ${customAppgwHelmConfig}
    sed -i -e "s:@APPGW_NAME@:${appgwName}:g" ${customAppgwHelmConfig}
    sed -i -e "s:@WATCH_NAMESPACE@:${wlsDomainNS}:g" ${customAppgwHelmConfig}
    sed -i -e "s:@SP_ENCODING_CREDENTIALS@:${spBase64String}:g" ${customAppgwHelmConfig}

    helm install ingress-azure \
        -f ${customAppgwHelmConfig} \
        application-gateway-kubernetes-ingress/ingress-azure \
        --version ${azureAppgwIngressVersion}

    utility_validate_status "Install app gateway ingress controller."

    attempts=0
    podState="running"
    while [ "$podState" == "running" ] && [ $attempts -lt ${checkPodStatusMaxAttemps} ]; do
        podState="completed"
        attempts=$((attempts + 1))
        echo Waiting for Pod running...${attempts}
        sleep ${checkPodStatusInterval}

        ret=$(kubectl get pod -o json |
            jq '.items[] | .status.containerStatuses[] | select(.name=="ingress-azure") | .ready')
        if [[ "${ret}" == "false" ]]; then
            podState="running"
        fi
    done

    if [ "$podState" == "running" ] && [ $attempts -ge ${checkPodStatusMaxAttemps} ]; then
        echo_stderr "Failed to install app gateway ingress controller."
        exit 1
    fi
}

function generate_appgw_cluster_config_file() {
    if [[ "${enableCustomSSL,,}" == "true" ]]; then
        generate_appgw_cluster_config_file_ssl
    else
        generate_appgw_cluster_config_file_nossl
    fi
}

function appgw_ingress_svc_for_cluster() {
    # generate ingress svc config for cluster
    generate_appgw_cluster_config_file
    kubectl apply -f ${clusterAppgwIngressYamlPath}
    utility_validate_status "Create appgw ingress svc."
    utility_waitfor_ingress_completed \
        ${clusterIngressName} \
        ${wlsDomainNS} \
        ${checkSVCStateMaxAttempt} \
        ${checkSVCInterval}

    # expose https for cluster if e2e ssl is not set up.
    if [[ "${enableCustomSSL,,}" != "true" ]]; then
        kubectl apply -f ${clusterAppgwIngressHttpsYamlPath}
        utility_validate_status "Create appgw ingress https svc."
        utility_waitfor_ingress_completed \
            ${clusterIngressHttpsName} \
            ${wlsDomainNS} \
            ${checkSVCStateMaxAttempt} \
            ${checkSVCInterval}
    fi
}

function create_gateway_ingress() {
    # query cluster port used for non-ssl or ssl
    query_cluster_target_port
    # create network peers between gateway vnet and aks vnet
    network_peers_aks_appgw
    # install azure ingress controllor
    install_azure_ingress

    # create ingress svc for cluster
    appgw_ingress_svc_for_cluster
}

# Initialize
script="${BASH_SOURCE[0]}"
scriptDir="$(cd "$(dirname "${script}")" && pwd)"

source ${scriptDir}/common.sh
source ${scriptDir}/utility.sh
source ${scriptDir}/createDnsRecord.sh

aksClusterRGName=$1
aksClusterName=$2
wlsDomainUID=$3
subID=$4
curRGName=$5
appgwName=$6
vnetName=$7

enableCookieBasedAffinity=${18}

adminServerName=${constAdminServerName} # define in common.sh
appgwIngressHelmRepo="https://appgwingress.blob.core.windows.net/ingress-azure-helm-package/"
appgwFrontCertFileName="appgw-frontend-cert.pfx"
appgwFrontCertKeyDecrytedFileName="appgw-frontend-cert.key"
appgwFrontCertKeyFileName="appgw-frontend-cert-decryted.key"
appgwFrontPublicCertFileName="appgw-frontend-cert.crt"
appgwFrontendSecretName="frontend-tls"
appgwBackendSecretName="backend-tls"
appgwSelfsignedCert="generateCert"
azureAppgwIngressVersion="1.4.0"
clusterName=${constClusterName}
httpsListenerName="myHttpsListenerName$(date +%s)"
httpsRuleName="myHttpsRule$(date +%s)"
svcAdminServer="${wlsDomainUID}-${adminServerName}"
svcCluster="${wlsDomainUID}-cluster-${clusterName}"
wlsDomainNS="${wlsDomainUID}-ns"

read_sensitive_parameters_from_stdin

create_gateway_ingress
