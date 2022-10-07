package http

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestArtifact(t *testing.T) {
	os.Setenv("TRIVY_DB_NAME", "scanner.db")
	af, err := NewArtifact("https://192.168.197.27/vuln/scanner.db.gz", false, WithToken("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo0MDk2LCJwMnMiOiJhWE4wVTJGc2RGTmhiWEJzWlEifQ.T5WH_yxtKQh-fLmkxFllmlo2flKcD0df8qiLDqIvUaZfRZKcd4SvzQ.YfzGlaznqZZ06cU_nadQ8g.vfGfQUazzRnqCi_mx1Pz2cCH7TE06WZd9I38Cn0NqP44D2FKKrijFXYx9-bsnswpVfY1RGdoEXAkmvUf6ojJr1gnWyDcQ1mIjFQ7K9JccaQD_nSt5SYSP8mlarsYktcQyDOmbsr82Kssr5ELH_JUFCiDSruimA2I_nxR66QzpatpsUyHTbVM-WoC5ej9jdh4QHiqIORU6EySMvPeLSOhg1Pyxo1p8PrlFQV-H6zU8IjTqlsblamC9ev40nQdwoZHRnG0KWYx9SJ8A5emvUmJNptpT4TXLlruFdoX5aHI74--czzPuAXFq40p2QInrckQFbYjKbW1yXRtpe8Q2-IFdaJSPiFzaw7BtI92_-k-_HyhEURLHv8U0o-WS7gYtAt6v0mI2kjNKtQZ2ubK9pRQpa6PBIxdZtqSc4RJiPXicXM.vKL3mctb_xbzzX6MUajYvw"))
	if err != nil {
		t.Error(err)
		return
	}

	err = af.Download(context.TODO(), "/tmp/scanner")
	if err != nil {
		t.Error(err)
		return
	}
}

func TestArtifactHead(t *testing.T) {
	os.Setenv("TRIVY_DB_NAME", "scanner.db")
	af, err := NewArtifact("https://192.168.2.178/vuln/scanner.db.gz", false, WithToken("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo0MDk2LCJwMnMiOiJhWE4wVTJGc2RGTmhiWEJzWlEifQ.6Uuryw5KQSegSdmDAmyNWs1gLjCKwvvMQZLcnmXCXb-2s16i5kxhYA.BH-MbR35PMmk8aTOL00r2Q._4KkREYbbuUO3afQll441X9XlMRncK3IGPC0xYbij4vzNnf3GrT3AeyuPnhHjxaWUHXTWXm2UsGHaou_lYl06b-2HNFfb9Q2Pz2uv4ROC9l2itF00-Ope8bK47dQsbef8aEEsvl2QQlBsDze7JOd27v6bEgBxtKO6gr_PlynFT8o8SrvJYaeIBRZWYWAcYS5IoLZG4Lt_pZqMWt47raOvIcehiTpKkmhSKZLtMyEHfj8A96LbLBAwSzpYjZgZKSpNtG5ncJzknHQUu8B7fXY0ofR1iXEPvBB8vLCMvwalQCYSFv0CSZcQxn82I8qC5JlQ6Vs2bQ2dYGjqwwusMxkGTMGqFYtF-y670ybbGt7x8NHfggWNFbknkW1wfxgFP0xkeUC29e8bOX6YBaLwmyk1zNXnb9g7DzLT5-l9FgwKMI.Di_nhfXQ6AXYkG_xNpSNiA"))
	if err != nil {
		t.Error(err)
		return
	}

	size, err := af.head(context.TODO())
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(size)
}

func TestArtifactUnauthorized(t *testing.T) {
	os.Setenv("TRIVY_DB_NAME", "scanner.db")
	af, err := NewArtifact("https://192.168.2.178/vuln/scanner.db.gz", false, WithToken("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo0MDk2LCJwMnMiOiJhWE4wVTJGc2RGTmhiWEJzWlEifQ.6Uuryw5KQSegSdmDAmyNWs1gLjCKwvvMQZLcnmXCXb-2s16i5kxhYA.BH-MbR35PMmk8aTOL00r2Q._4KkREYbbuUO3afQll441X9XlMRncK3IGPC0xYbij4vzNnf3GrT3AeyuPnhHjxaWUHXTWXm2UsGHaou_lYl06b-2HNFfb9Q2Pz2uv4ROC9l2itF00-Ope8bK47dQsbef8aEEsvl2QQlBsDze7JOd27v6bEgBxtKO6gr_PlynFT8o8SrvJYaeIBRZWYWAcYS5IoLZG4Lt_pZqMWt47raOvIcehiTpKkmhSKZLtMyEHfj8A96LbLBAwSzpYjZgZKSpNtG5ncJzknHQUu8B7fXY0ofR1iXEPvBB8vLCMvwalQCYSFv0CSZcQxn82I8qC5JlQ6Vs2bQ2dYGjqwwusMxkGTMGqFYtF-y670ybbGt7x8NHfggWNFbknkW1wfxgFP0xkeUC29e8bOX6YBaLwmyk1zNXnb9g7DzLT5-l9FgwKMI.Di_nhfXQ6AXYkG_xNpSNiA"))
	if err != nil {
		t.Error(err)
		return
	}

	contentLength := 42807158

	file, err := os.OpenFile("/tmp/test.dat", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	defer file.Close()

	size, err := af.download(context.TODO(), file, 0, int64(contentLength))
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(size)
}

func TestArtifactDownload(t *testing.T) {
	os.Setenv("TRIVY_DB_NAME", "scanner.db")
	af, err := NewArtifact("https://192.168.2.178/vuln/scanner.db.gz", false, WithToken("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo0MDk2LCJwMnMiOiJhWE4wVTJGc2RGTmhiWEJzWlEifQ.6Uuryw5KQSegSdmDAmyNWs1gLjCKwvvMQZLcnmXCXb-2s16i5kxhYA.BH-MbR35PMmk8aTOL00r2Q._4KkREYbbuUO3afQll441X9XlMRncK3IGPC0xYbij4vzNnf3GrT3AeyuPnhHjxaWUHXTWXm2UsGHaou_lYl06b-2HNFfb9Q2Pz2uv4ROC9l2itF00-Ope8bK47dQsbef8aEEsvl2QQlBsDze7JOd27v6bEgBxtKO6gr_PlynFT8o8SrvJYaeIBRZWYWAcYS5IoLZG4Lt_pZqMWt47raOvIcehiTpKkmhSKZLtMyEHfj8A96LbLBAwSzpYjZgZKSpNtG5ncJzknHQUu8B7fXY0ofR1iXEPvBB8vLCMvwalQCYSFv0CSZcQxn82I8qC5JlQ6Vs2bQ2dYGjqwwusMxkGTMGqFYtF-y670ybbGt7x8NHfggWNFbknkW1wfxgFP0xkeUC29e8bOX6YBaLwmyk1zNXnb9g7DzLT5-l9FgwKMI.Di_nhfXQ6AXYkG_xNpSNiA"))
	if err != nil {
		t.Error(err)
		return
	}

	err = af.Download(context.TODO(), "/tmp/cache")
	if err != nil {
		t.Error(err)
		return
	}
}

func TestValidate(t *testing.T) {
	os.Setenv("TRIVY_DB_NAME", "scanner.db.1")
	var (
		in, out *os.File
		err     error
	)

	if in, err = os.Open("/tmp/cache/db/scanner.db"); err != nil {
		t.Error(err)
		return
	}
	defer in.Close()

	if out, err = os.Create("/tmp/cache/db/scanner.db.1"); err != nil {
		t.Error(err)
		return
	}
	defer out.Close()

	_, err = io.CopyN(out, in, 42807150)
	if err != nil {
		t.Error(err)
		return
	}

	af := &Artifact{}
	t.Log(af.validate("/tmp/cache", errors.New("test")))
}

func TestNeedUpdate(t *testing.T) {
	os.Setenv("TRIVY_DB_NAME", "scanner.db")
	date := time.Date(2024, 6, 26, 12, 15, 18, 0, time.Local)
	af, err := NewArtifact("https://192.168.2.100/vuln/scanner.db.gz", false, WithDownloadTime(date), WithToken("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo0MDk2LCJwMnMiOiJhWE4wVTJGc2RGTmhiWEJzWlEifQ.ubGtMdnGS_oluA9hfSleC6qGSJ9f49PfLcEoEafYbF-vu7TW_6VxaA.P0GgZ7wIsb7NjAidFwo9zQ.BMSP9djqYslnsz_18uBIOlJE20LCn_v_CDdwgD6p5Jkvi46npZ_6JAEoR3zRqKZHAm4bDXAJhLbIwLdl-KQETQsHjS4UPgEQK1kVrQddh8cVVMJW0nMxO9JmQ5piZygdmKJLUNSpAfckVYGydRSTTTQlqJOKm73_1NGCmsygKAjZhcRR6Qr9KMhjMBDBBstY-IWCnPBFIQDr6N4EAeVpzIsIyax-MzEVRL5uj3LHgMyGxTL7VwdrP7hJgG15bTPP_ntjQONX7331lD53cKWUvLsvTH1DjacryUx_s-i5i8y6zocCk_dSXsz3wFLBevqlz2IbC4GarP0Q6nKU22mshIv0J2j2LxVSZQhf5JclTuSAQY5wnPTxWMtOoBhNxSgoj7tuewt4YukrsBUfZIaZwkWEKqik1a5sQArk8RhcXHs.lYlN5oxjQvzjjAub05LC0g"))
	if err != nil {
		t.Error(err)
		return
	}

	needUpdate, err := af.NeedUpdate()
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(needUpdate)
}
