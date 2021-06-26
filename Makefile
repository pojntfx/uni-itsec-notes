all: build

.PHONY: docs
docs:
	mkdir -p out/docs
	if [ -d "docs/static" ]; then cp -r docs/static out/docs; fi
	echo "<!DOCTYPE html><meta charset="utf-8"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><meta name=\"description\" content=\"$$(sed -n '2 p' docs/metadata.txt)\"><link rel=\"stylesheet\" href=\"https://unpkg.com/marx-css/css/marx.min.css\"><title>$$(sed -n '1 p' docs/metadata.txt)</title><main><h1>$$(sed -n '1 p' docs/metadata.txt)</h1><p>$$(sed -n '2 p' docs/metadata.txt)</p><hr><a href=\"$$(sed -n '4 p' docs/metadata.txt)\" target=\"_blank\">📃 View source (✍️ $$(sed -n '3 p' docs/metadata.txt))</a><br><a href=\"$$(sed -n '5 p' docs/metadata.txt)\" download=\"$$(sed -n '1 p' docs/metadata.txt).zip\">📥 Download all as ZIP</a><hr><div>You may do the following:</div><ul>" > "out/docs/index.html"
	for document in docs/*.md; do\
		echo "Compiling $${document} ..." ;\
    	docker run -v "$(PWD):/data:z" pandoc/latex "$${document}" -o "out/$${document}.pdf" & docker run -v "$(PWD):/data:z" pandoc/latex "$${document}" --toc --self-contained -t html5 -o "out/$${document}.html" & docker run -v "$(PWD):/data:z" pandoc/latex "$${document}" --self-contained -t slidy --slide-level 3 -o "out/$${document}.slides.html" & docker run -v "$(PWD):/data:z" pandoc/latex "$${document}" -t beamer --slide-level 3 -o "out/$${document}.slides.pdf";\
		echo "<li><a href=\"$${document#docs/}.html\" target=\"_blank\">🌐 View $${document#docs/} in your browser</a> (also available as <a href=\"$${document#docs/}.slides.html\" target=\"_blank\">slides</a>) or <a href=\"$${document#docs/}.pdf\" target=\"_blank\">📥 download $${document#docs/} as PDF</a> (also available as <a href=\"$${document#docs/}.slides.pdf\" target=\"_blank\">slides</a>)" >> "out/docs/index.html";\
	done
	echo "</ul><div><strong><em>$$(sed -n '6 p' docs/metadata.txt)</em></strong></div></main>" >> "out/docs/index.html"
	mkdir -p "out/release"
	zip -j -r "out/release/all.zip" "out/docs"

build: docs

dev:
	while [ -z "$${MAKE_PID}" ] || [ -n "$$(inotifywait -q -r -e modify docs/*.md)" ]; do\
		$(MAKE) PWD=$(PWD) & export MAKE_PID="$$!";\
	done

clean:
	rm -rf out

depend:
	docker pull pandoc/latex