package runner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aleister1102/crlfuzz/pkg/crlfuzz"
	"github.com/aleister1102/crlfuzz/pkg/errors"
	"github.com/logrusorgru/aurora"
)

// New will fuzz target line by line
func New(options *Options) {
	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				options.run(target)
			}
		}()
	}

	for _, line := range strings.Split(options.Target, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if isURL(line) {
			for _, url := range crlfuzz.GenerateURL(line) {
				jobs <- url
			}
		}
	}

	close(jobs)
	wg.Wait()
}

func (options *Options) run(url string) {
	// Show URL being tested in verbose mode
	if options.Verbose && !options.Silent {
		fmt.Printf("[%s] %s\n", aurora.Blue("TST").String(), url)
	}

	v, e := crlfuzz.Scan(
		url,
		options.Method,
		options.Data,
		options.Headers,
		options.Proxy,
	)

	url = strings.Trim(fmt.Sprintf("%q", url), "\"")

	if e != nil {
		if !options.Silent && options.Verbose {
			errors.Show(fmt.Sprintf("%s: %s", url, e.Error()))
		}
	}

	if v {
		if options.Silent {
			fmt.Println(url)
		} else {
			fmt.Printf("[%s] %s\n", aurora.Green("VLN").String(), aurora.Green(url).String())
		}

		if options.Output != nil {
			_, f := options.Output.WriteString(fmt.Sprintf("%s\n", url))
			if f != nil {
				errors.Show(f.Error())
			}
		}
	}
}
