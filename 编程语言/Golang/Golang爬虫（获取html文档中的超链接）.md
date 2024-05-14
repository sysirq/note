```go
package main

import(
	"fmt"
	"net/http"
	"io/ioutil"
	"regexp"
	"strings"
)

var href_reg *regexp.Regexp

var hrefs_been_found map[string]int

var hrefs_undone []string

func get_all_href(url string)([]string){
	var ret [] string
	resp,err := http.Get(url)
	if err!=nil {
		fmt.Println(err)
		return ret
	}
	defer resp.Body.Close()
	body,_ := ioutil.ReadAll(resp.Body)
	

	hrefs := href_reg.FindAllString(string(body),-1)
	
	for _,v := range hrefs{
		str := strings.Split(v,"\"")[1]
		
		if len(str)<1{
			continue
		}

		switch str[0]{
		case 'h':
			ret = append(ret,str)	
		case '/':
			if len(str)!=1 && str[1]=='/'{
				ret = append(ret,"http:"+str)	
			}
			
			if len(str)!=1 && str[1]!='/'{
				ret = append(ret,url+str[1:])
			}
		default:
			ret = append(ret,url+str)
			
		}
		
	}

	return ret
}

func init_global_var(){
	href_pattern :=   "href=\"(.+?)\""
	href_reg = regexp.MustCompile(href_pattern)

	hrefs_been_found = make(map[string]int)
}

func is_href_been_found(href string)bool{
	_,ok := hrefs_been_found[href]
	return ok
}

func add_hrefs_to_undone_list(hrefs []string){
	for _,value := range hrefs {
		ok := is_href_been_found(value)
		if !ok {
			fmt.Printf("new url:(%s)\n",value);
			hrefs_undone = append(hrefs_undone,value)
			hrefs_been_found[value]=1
		}else{
			hrefs_been_found[value]++
		}
		
	}
}

func main(){
	init_global_var()

	var pos = 0
	var urls = []string{"http://www.baidu.com"}
	add_hrefs_to_undone_list(urls)
	
	for {
		if pos >= len(hrefs_undone) {
			break
		}
		url:= hrefs_undone[0]
		hrefs_undone = hrefs_undone[1:]

		hrefs := get_all_href(url)
		add_hrefs_to_undone_list(hrefs)
	}
}
```