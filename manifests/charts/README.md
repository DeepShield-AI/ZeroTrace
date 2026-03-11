# ZeroTrace Helm Charts

ZeroTrace helm chart repo: https://github.com/zerotraceio/zerotrace-charts

An automated observability platform for cloud-native developers.

This repository contains [Helm](https://helm.sh/) charts for ZeroTrace project.

## Usage

[Helm](https://helm.sh) must be installed to use the charts.
Please refer to Helm's [documentation](https://helm.sh/docs/) to get started.

Once Helm is set up properly, add the repo as follows:

```console
helm repo add zerotrace https://zerotraceio.github.io/zerotrace
helm repo update zerotrace
```

## Helm Charts

You can then run `helm search repo zerotrace` to see the charts.

_See [helm repo](https://helm.sh/docs/helm/helm_repo/) for command documentation._

## Installing the Chart

To install the chart with the release name `zerotrace`:

```console
helm install zerotrace -n zerotrace zerotrace/zerotrace --create-namespace
```

## Uninstalling the Chart

To uninstall/delete the my-release deployment:

```console
helm delete zerotrace -n zerotrace
```

The command removes all the Kubernetes components associated with the chart and deletes the release.


## License

[Apache 2.0 License](../../LICENSE).