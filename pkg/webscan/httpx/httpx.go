package httpx

import (
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
	"io/ioutil"
	"log"
	"os"
	"time"
)

type T struct {
	Timestamp time.Time `json:"timestamp"`
	Hash      struct {
		BodyMd5       string `json:"body_md5"`
		BodyMmh3      string `json:"body_mmh3"`
		BodySha256    string `json:"body_sha256"`
		BodySimhash   string `json:"body_simhash"`
		HeaderMd5     string `json:"header_md5"`
		HeaderMmh3    string `json:"header_mmh3"`
		HeaderSha256  string `json:"header_sha256"`
		HeaderSimhash string `json:"header_simhash"`
	} `json:"hash"`
	Port        string   `json:"port"`
	Url         string   `json:"url"`
	Input       string   `json:"input"`
	Location    string   `json:"location"`
	Scheme      string   `json:"scheme"`
	Webserver   string   `json:"webserver"`
	ContentType string   `json:"content_type"`
	Method      string   `json:"method"`
	Title       string   `json:"title"`
	Host        string   `json:"host"`
	Path        string   `json:"path"`
	Time        string   `json:"time"`
	A           []string `json:"a"`
	Words       int      `json:"words"`
	Lines       int      `json:"lines"`
	StatusCode  int      `json:"status_code"`
	Failed      bool     `json:"failed"`
}

func HttpxSubdomain(domain []string, path string) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

	options := runner.Options{
		Methods:         "GET",
		OutputCDN:       true,
		StatusCode:      true,
		ExcludeCDN:      true,
		JSONOutput:      true,
		ExtractTitle:    true,
		InputTargetHost: goflags.StringSlice(domain),
		Output:          path,
	}
	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

}
func HttpxJsonRead(path string) (Url string, StatusCode int, Title string) {
	var domainList []string
	jsonFile, err := os.Open(path)

	// 最好要处理以下错误
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var t T
	json.Unmarshal([]byte(byteValue), &t)
	//判断是否有location跳转
	if t.Location != "" {
		fmt.Println("不为空" + t.Location)

		domainList = append(domainList, t.Location)

		HttpxSubdomain(domainList, "targetDomains.json")
		//jsonFile.Close()
		HttpxJsonRead("targetDomains.json")
	}
	return t.Url, t.StatusCode, t.Title

}
func run(domain []string, path string) {

	HttpxSubdomain(domain, path)
	url, StatusCode, Title := HttpxJsonRead(path)
	fmt.Println(url, StatusCode, Title)
}
