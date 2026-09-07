LATEXMK ?= latexmk

SRC_DIR := manual
TARGET := manual
SRC := $(SRC_DIR)/$(TARGET).tex
BUILD_PDF := $(SRC_DIR)/$(TARGET).pdf
OUTPUT_PDF := $(TARGET).pdf

.PHONY: all pdf clean

all: pdf

pdf: $(OUTPUT_PDF)

$(OUTPUT_PDF): $(SRC) $(SRC_DIR)/*.tex $(SRC_DIR)/*.bib
	$(LATEXMK) -pdf -cd $(SRC)
	cp $(BUILD_PDF) $(OUTPUT_PDF)

clean:
	$(LATEXMK) -C -cd $(SRC)
	rm -f $(OUTPUT_PDF)
	rm -f $(TARGET).aux $(TARGET).bbl $(TARGET).blg $(TARGET).log
	rm -f $(TARGET).out $(TARGET).toc $(TARGET).fdb_latexmk $(TARGET).fls
