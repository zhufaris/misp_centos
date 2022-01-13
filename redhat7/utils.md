### create instance in gcp
```bash

```



```bash
gcloud beta compute ssh --zone "asia-southeast1-b" "misp3"  --project "security-analytics-291012"
```


```bash
gcloud compute  ssh --ssh-flag="-L 8080:localhost:80"  --zone "asia-southeast1-b" "mip-demo"  --project "security-analytics-291012"
```


gcloud beta compute ssh --zone "asia-southeast1-b" "mip-demo"  --project "security-analytics-291012"