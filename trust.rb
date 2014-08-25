#!/usr/bin/ruby

# Name:         trust (To RUn SheeT)
# Version:      0.0.4
# Release:      1
# License:      Open Source
# Group:        System
# Source:       N/A
# URL:          http://lateralblast.com.au/
# Distribution: Solaris, Red Hat Linux, SuSE Linux, Debian Linux,
#               Ubuntu Linux, Mac OS X, AIX FreeBSD
# Vendor:       UNIX
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Converts CIS (and other) PDFs into text or a CSV/XLS run sheet
#

# Required modules:

require 'getopt/std'
require 'pathname'
require 'fileutils'
require 'writeexcel'

# Add code to strip control characters to string class

class String
  def stripcc()
    self.chars.inject("") do |str, char|
      unless char.ascii_only? and (char.ord < 32 or char.ord == 127)
        str << char
      end
      str
    end
  end
  def stripec()
    self.chars.inject("") do |str, char|
      if char.ascii_only? and char.ord.between?(32,126)
        str << char
      end
      str
    end
  end
end

# Get command line options

options = "acd:hf:lo:p:r:tvVx"

# Set variables

base_dir = Dir.pwd
pdf_dir  = base_dir+"/pdfs"

# Print the version of the script

def print_version()
  puts
  file_array = IO.readlines $0
  version    = file_array.grep(/^# Version/)[0].split(":")[1].gsub(/^\s+/,'').chomp
  packager   = file_array.grep(/^# Packager/)[0].split(":")[1].gsub(/^\s+/,'').chomp
  name       = file_array.grep(/^# Name/)[0].split(":")[1].gsub(/^\s+/,'').chomp
  puts name+" v. "+version+" "+packager
  puts
  return
end

# Print information regarding the usage of the script

def print_usage(options)
  puts
  puts "Usage: "+$0+" -["+options+"]"
  puts
  puts "-V:\tDisplay version information"
  puts "-h:\tDisplay usage information"
  puts "-a:\tProcess all PDFs"
  puts "-d:\tSet PDF directory"
  puts "-f:\tProcess a file"
  puts "-l:\tList all pdf files"
  puts "-p:\tSet product"
  puts "-r:\tSet release"
  puts "-o:\tOutput to file"
  puts "-t:\tOutput in TXT mode"
  puts "-c:\tOutput in CSV mode"
  puts "-x:\tOutput in XLS mode"
  puts "-v:\tVerbose mode"
  puts
  return
end

# Get a list of PDF files

def get_pdf_list(pdf_dir)
  pdf_list = []
  pdf_files = Dir.entries(pdf_dir)
  pdf_files.each do |file_name|
    if file_name.match(/pdf$/) and file_name.match(/^CIS/)
      pdf_file = pdf_dir+"/"+file_name
      pdf_file = pdf_file.chomp
      pdf_list.push(pdf_file)
    end
  end
  return pdf_list
end

# Process PDF files
# If a text file doesn't exist create one

def process_pdf_file(pdf_file)
  pdf_dir   = Pathname.new(pdf_file)
  pdf_dir   = pdf_dir.dirname.to_s
  file_name = File.basename(pdf_file,".pdf").chomp
  txt_file  = pdf_dir+"/"+file_name+".txt"
  if !File.exist?(txt_file)
    puts "Convering "+pdf_file+" to "+txt_file
    %x[pdftotext #{pdf_file}]
    %x[dos2unix #{txt_file}]
  end
  return txt_file
end

# Process text file

def process_txt_file(txt_file,output_mode,output_file)
  if output_file.match(/[A-z]/)
    if output_mode == "xls"
      row_no    = 1
      workbook  = WriteExcel.new(output_file)
      name      = "CIS Runsheet"
      worksheet = workbook.add_worksheet(name)
      format    = workbook.add_format
      header    = workbook.add_format
      header.set_bold(1)
      header.set_text_wrap
      header.set_align('center')
      worksheet.write('A1','Source',header)
      worksheet.set_column(1, 0,  20)
      worksheet.write('B1','Document',header)
      worksheet.write('C1','Version',header)
      worksheet.write('D1','Section',header)
      worksheet.write('E1','Page',header)
      worksheet.set_column(5, 0,  20)
      worksheet.write('F1','Test',header)
      worksheet.write('G1','Level',header)
      worksheet.write('H1','Vendor',header)
      worksheet.write('I1','OS',header)
      worksheet.write('J1','Release',header)
      worksheet.set_column(10, 0,  80)
      worksheet.write('K1','Description',header)
      worksheet.set_column(11, 0,  80)
      worksheet.write('L1','Rationale',header)
      worksheet.set_column(12, 0,  80)
      worksheet.write('M1','Audit',header)
      worksheet.set_column(13, 0,  80)
      worksheet.write('N1','Remediation',header)
      worksheet.write('O1','Impact',header)
      format.set_bold(0)
      format.set_text_wrap
      format.set_align('left')
    else
      file = File.open(output_file,"w")
    end
  end
  if output_mode == "csv"
    if output_file.match(/[A-z]/)
      file.write("Source,Document,Version,Section,Page,Test,Level,Vendor,OS,Release,Check,Fix,Description,Rationale,Audit,Remediation,Impact\n")
    else
      puts "Source,Document,Version,Section,Page,Test,Level,Vendor,OS,Release,Check,Fix,Description,Rationale,Audit,Remediation,Impact"
    end
  end
  file_name = File.basename(txt_file,".txt")
  file_info = file_name.split("_")
  if file_name.match(/Red/)
    vendor = file_info[1..2].join(" ")
  else
    vendor = file_info[1]
  end
  case vendor
  when /Apple|CentOS|Oracle|VMware|IBM/
    os_name = file_info[2]
    os_ver  = file_info[3]
  when /Red/
    os_name = file_info[3..4].join(" ")
    os_ver  = file_info[5]
  when /SUSE/
    os_name = file_info[2..4].join(" ")
    os_ver  = file_info[5]
  else
    os_name = file_info[2..3].join(" ")
    os_ver  = file_info[4]
  end
  doc_ver        = file_info[-1].gsub(/v/,"")
  file_text      = []
  file_text      = %x[cat #{txt_file} |egrep '[A-z]|[0-9]' |grep -v '^-o$'].split("\n")
  first_test     = 1
  section_no     = ""
  page_no        = ""
  test_name      = ""
  description    = []
  remediation    = []
  rationale      = []
  audit          = []
  references     = []
  check          = []
  fix            = []
  applicable     = []
  impact         = []
  counter        = 0
  do_description = 0
  do_remediation = 0
  do_rationale   = 0
  do_audit       = 0
  do_references  = 0
  do_applicable  = 0
  do_impact      = 0
  file_text.each do |line|
    counter = counter + 1
    line    = line.stripec
    line    = line.chomp
    if line.match(/[A-z]|[0-9]/)
      case line
      when /P a g e$|Page$/
        page_no = line.gsub(/[A-z]|\||\s+/,"")
      when /Scored\)$|Appendix:$/
        if first_test != 1
          if output_mode == "xls"
            description = description.join("\r")
            rationale   = rationale.join("\r")
            audit       = audit.join("\r")
            check       = check.join(" ; ").gsub(/\| ;/," ; ")
            fix         = fix.join(" ; ").gsub(/\| ;/," ; ")
            remediation = remediation.join("\r")
            impact      = impact.join("\r")
            applicable  = applicable.join
            doc_name    = file_name+".pdf"
            worksheet.write(row_no,0,'CIS',format)
            worksheet.write(row_no,1,doc_name,format)
            worksheet.write(row_no,2,doc_ver,format)
            worksheet.write(row_no,3,section_no,format)
            worksheet.write(row_no,4,page_no,format)
            worksheet.write(row_no,5,test_name,format)
            worksheet.write(row_no,6,applicable,format)
            worksheet.write(row_no,7,vendor,format)
            worksheet.write(row_no,8,os_name,format)
            worksheet.write(row_no,9,os_ver,format)
            worksheet.write(row_no,10,description,format)
            worksheet.write(row_no,11,rationale,format)
            worksheet.write(row_no,12,audit,format)
            worksheet.write(row_no,13,remediation,format)
            worksheet.write(row_no,14,impact,format)
            row_no = row_no+1
          end
          if output_mode == "txt"
            description = description.join("\n").gsub(/"/,"'")
            rationale   = rationale.join("\n").gsub(/"/,"'")
            audit       = audit.join("\n").gsub(/"/,"'")
            check       = check.join(" ; ").gsub(/\| ;/," ; ")
            fix         = fix.join(" ; ").gsub(/\| ;/," ; ")
            remediation = remediation.join("\n").gsub(/"/,"'")
            impact      = impact.join("\n").gsub(/"/,"'")
            applicable  = applicable.join
            if output_file.match(/[A-z]/)
              file.write("\n")
              file.write("Resource:    CIS\n")
              file.write("File:        #{file_name}.pdf\n")
              file.write("Version      #{doc_ver}\n")
              file.write("Section:     #{section_no}\n")
              file.write("Page:        #{page_no}\n")
              file.write("Test:        #{test_name}\n")
              file.write("Level:       #{applicable}\n")
              file.write("Vendor:      #{vendor}\n")
              file.write("OS:          #{os_name}\n")
              file.write("OS Rel:      #{os_ver}\n")
              file.write("Impact\n#{impact}\n")
              file.write("Description:\n#{description}\n")
              file.write("Rationale:\n#{rationale}\n")
              file.write("Audit:\n#{audit}\n")
              file.write("Check:\n#{check}\n")
              file.write("Remediation:\n#{remediation}\n")
              file.write("Fix:\n#{fix}\n")
              file.write("Impact:\n#{impact}\n")
            else
              puts
              puts "Resource:    CIS"
              puts "File:        "+file_name+".pdf"
              puts "Version      "+doc_ver
              puts "Section:     "+section_no
              puts "Page:        "+page_no
              puts "Test:        "+test_name
              puts "Level:       "+applicable
              puts "Vendor:      "+vendor
              puts "OS:          "+os_name
              puts "OS Rel:      "+os_ver
              puts "Impact:\n"+impact
              puts "Description:\n"+description
              puts "Rationale:\n"+rationale
              puts "Audit:\n"+audit
              if check
                puts "Check:\n"+check
              end
              puts "Remediation:\n"+remediation
              if fix
                puts "Fix:\n"+fix
              end
              puts "Impact:\n"+impact
            end
          end
          if output_mode == "csv"
            description = description.join(" ").gsub(/"/,"'")
            rationale   = rationale.join(" ").gsub(/"/,"'")
            audit       = audit.join(" ").gsub(/"/,"'")
            check       = check.join(" ; ").gsub(/\| ;/," ; ").gsub(/; '/," '").gsub(/; >/,">").gsub(/ ; ([A-Z])/) { " #{$1}"}
            if check.match(/,/)
              check = check.gsub(/"/,"'")
              check = '"'+check+'"'
            end
            fix         = fix.join(" ; ").gsub(/\| ;/," ; ").gsub(/; '/," '").gsub(/; >/,">").gsub(/ ; ([A-Z])/) { " #{$1}"}
            if fix.match(/,/)
              fix = fix.gsub(/"/,"'")
              fix = '"'+fix+'"'
            end
            remediation = remediation.join(" ").gsub(/"/,"'")
            impact      = impact.join(" ").gsub(/"/,"'")
            applicable  = applicable.join
            if output_file.match(/[A-z]/)
              file.write("CIS,#{file_name},#{doc_ver},#{section_no},#{page_no},#{test_name},#{applicable},#{vendor},#{os_name},#{os_ver},#{check},#{fix},\"#{impact}\",\"#{description}\".\"#{rationale}\",\"#{audit}\",\"#{remediation}\"\n")
            else
              puts "CIS,"+file_name+","+doc_ver+","+section_no+","+page_no+","+test_name+","+applicable+","+vendor=","+os_name+","+os_ver+","+check+","+fix+",\""+impact+"\".\""+description+"\".\""+rationale+"\",\""+audit+"\",\""+remediation+"\""
            end
          end
        else
          first_test = 0
        end
        if line.match(/Scored/) and !line.match(/^[0-9]/)
          if !file_text[counter-2].match(/[A-z]|[0-9]/)
            text_info   = file_text[counter-3].split(/\s+/)
          else
            text_info   = file_text[counter-2].split(/\s+/)
          end
          section_no  = text_info[0]
          test_name   = text_info[1..-1].join(" ")
        else
          section_no  = line.split(/\s+/)[0]
          test_name   = line.split(/\(/)[0].split(/\s+/)[1..-1].join(" ")
        end
        test_name   = test_name.gsub(/"|,/,"")
        description = []
        remediation = []
        rationale   = []
        audit       = []
        references  = []
        check       = []
        fix         = []
        applicable  = []
        impact      = []
      when /Profile Applicability:/
        do_applicable  = 1
        do_description = 0
        do_remediation = 0
        do_rationale   = 0
        do_audit       = 0
        do_references  = 0
        do_impact      = 0
      when /^Description:/
        do_description = 1
        do_remediation = 0
        do_rationale   = 0
        do_audit       = 0
        do_references  = 0
        do_applicable  = 0
        do_impact      = 0
      when /^Remediation:/
        do_remediation = 1
        do_description = 0
        do_rationale   = 0
        do_audit       = 0
        do_references  = 0
        do_applicable  = 0
        do_impact      = 0
      when /^Rationale:/
        do_rationale   = 1
        do_remediation = 0
        do_description = 0
        do_audit       = 0
        do_references  = 0
        do_applicable  = 0
        do_impact      = 0
      when /^Audit:/
        do_audit       = 1
        do_remediation = 0
        do_description = 0
        do_rationale   = 0
        do_references  = 0
        do_applicable  = 0
        do_impact      = 0
      when /^References:/
        do_references  = 1
        do_audit       = 0
        do_remediation = 0
        do_description = 0
        do_rationale   = 0
        do_applicable  = 0
        do_impact      = 0
      when /^Impact:/
        do_impact      = 1
        do_references  = 0
        do_audit       = 0
        do_remediation = 0
        do_description = 0
        do_rationale   = 0
        do_applicable  = 0
      end
      if do_applicable == 1 and !line.match(/^Profile Applicability|Page$|P a g e$|Scored/) and line.match(/[A-z]|[0-9]/)
        if !line.match(/^[0-9]\.$/)
          if file_text[counter-2].match(/^[0-9]\.$/)
            line = file_text[counter-2]+" "+line
          end
          line = line.gsub(/Level /,"")
          applicable.push(line)
        end
      end
      if do_description == 1 and !line.match(/^Description|Page$|P a g e$|Scored/) and line.match(/[A-z]/)
        if !line.match(/^[0-9]\.$/)
          if file_text[counter-2].match(/^[0-9]\.$/)
            line = file_text[counter-2]+" "+line
          end
          description.push(line)
        end
      end
      if do_remediation == 1 and !line.match(/^Remediation|Page$|P a g e$|Scored/) and line.match(/[A-z]|[0-9]/)
        if !line.match(/^[0-9]\.$/)
          if file_text[counter-2].match(/^[0-9]\.$/)
            line = file_text[counter-2]+" "+line
          end
          remediation.push(line)
          if line.match(/^\.\/|^#|^\$|^\\|\||grep |sudo |^defaults |chkconfig |yum |perl |sysctl |find |awk |echo |^done |^for |[a-z]=[0-9]|[a-z]\.[a-z]| -[A-z]/) or file_text[counter-2].match(/:$|\\$/) and !file_text[counter-2].match(/[V,v]alue|[E,e]nabled|Off:|Only:|[C,c]onfiguration:|similar|follows/)
            if file_text[counter-2].match(/\\$/)
              previous = file_text[counter-2].to_s.gsub(/\\$/,"").gsub(/\n/,"")
              line     = previous+line
            end
            if !line.match(/^definact|^PM|^root|^IP|^#\!|^\/tmp|^\/etc|^fs\.|^\/var|^password|^PASS|^options|^NET|^net\.|^-[A-z]|\|\|$|\{$|true$|^\$[A-Z][a-z]|Ensure|OS|N\/A|\[\]:|^o |^[0-9]|[a-z]ing|Preferences:|^YES|[A-z]\. [A-Z]|^##|[a-z]\.$|^# page|URL|XX|^# rotate|^# keep|combined$|^# images|^<[A-Z]|^#<[A-Z]|^#<\/[A-Z]|passwd:|[a-z][a-z]:$|^\*|^>|^body|^#[A-Z]|^# [A-Z]|body|header|timestamp|^<|^@|^No|[V,v]alue|[C,c]onfigured|[E,e]nabled|2[0-9][0-9][0-9]|groups|Error|Load|download|welcome|[D,d]ocument|[S,s]ecurity|[V,v]unerable|[A,a]vailable|proxy_[a-z]|[E,e]xample |[E,e]xpired|Verify|[C,c]onfiguration|loaded|^http|information|html|servername|^Options| the | does | can |^file|Password|AIDE|^id:|^restrict|^server|^auth|^kern|^daemon|^syslog|^lpr|^always|directory| may /)
              line = line.gsub(/ \\$/,"")
              line = line.gsub(/^#|^\$ |^\\/,"")
              line = line.gsub(/^\s+/,"")
              line = line.gsub(/ \\$/,"")
              if line.match(/^\/ \\\(/)
                line = "find "+line
              end
              fix.push(line)
              fix = fix.uniq
            end
          end
        end
      end
      if do_rationale == 1 and !line.match(/^Rationale|Page$|P a g e$|Scored/) and line.match(/[A-z]|[0-9]/)
        rationale.push(line)
      end
      if do_audit == 1 and !line.match(/^Audit|Page$|P a g e$|Scored/) and line.match(/[A-z]|[0-9]/)
        if !line.match(/^[0-9]\.$/)
          if file_text[counter-2].match(/^[0-9]\.$/)
            line = file_text[counter-2]+" "+line
          end
          audit.push(line)
          if line.match(/^\.\/|^#|^\$|^\\|\||grep |sudo |^defaults |chkconfig |yum |perl |sysctl |find |awk |echo |^done |^for |[a-z]=[0-9]|[a-z]\.[a-z]| -[A-z]/) or file_text[counter-2].match(/:$|\\$/) and !file_text[counter-2].match(/[V,v]alue|[C,c]onfigured|[E,e]nabled|Off:|Only:|similar|follows/)
            if file_text[counter-2].match(/\\$/)
              previous = file_text[counter-2].to_s.gsub(/\\$/,"").gsub(/\n/,"")
              line     = previous+line
            end
            if !line.match(/^definact|^PM|^root|^IP|^#\!|^\/tmp|^\/etc|^fs\.|^\/var|^password|^PASS|^options|^NET|^net\.|^-[A-z]|\|\|$|\{$|true$|^\$[A-Z][a-z]|Ensure|OS|N\/A|\[\]:|^o |^[0-9]|[a-z]ing|Preferences:|^YES|[A-z]\. [A-Z]|^##|[a-z]\.$|^# page|URL|XX|^# rotate|^# keep|combined$|^# images|^<[A-Z]|^#<[A-Z]|^#<\/[A-Z]|passwd:|[a-z][a-z]:$|^\*|^>|^body|^#[A-Z]|^# [A-Z]|body|header|timestamp|^<|^@|^No|[V,v]alue|[C,c]onfigured|[E,e]nabled|2[0-9][0-9][0-9]|groups|Error|Load|download|welcome|index|[D,d]ocument|[S,s]ecurity|[V,v]unerable|[A,a]vailable|proxy_[a-z]|[E,e]xample |[E,e]xpired|Verify|[C,c]onfiguration|loaded|^http|information|html|servername|^Options| the | does | can |^file|Password|AIDE|^id:|^restrict|^server|^auth|^kern|^daemon|^syslog|^lpr|^always|directory| may /)
              line = line.gsub(/ \\$/,"")
              line = line.gsub(/^#|^\$ |^\\/,"")
              line = line.gsub(/^\s+/,"")
              line = line.gsub(/ \\$/,"")
              if line.match(/^\/ \\\(/)
                line = "find "+line
              end
              check.push(line)
              check = check.uniq
            end
          end
        end
      end
      if do_references == 1 and !line.match(/^References|Page$|P a g e$|Scored/) and line.match(/[A-z]|[0-9]/)
        if !line.match(/^[0-9]\.$/)
          if file_text[counter-2].match(/^[0-9]\.$/)
            line = file_text[counter-2]+" "+line
          end
          references.push(line)
        end
      end
      if do_impact == 1 and !line.match(/^Impact|Page$|P a g e$|Scored/)
        if !line.match(/^[0-9]\.$/)
          if file_text[counter-2].match(/^[0-9]\.$/)
            line = file_text[counter-2]+" "+line
          end
          impact.push(line)
        end
      end
    end
  end
  if output_file.match(/[A-z]/)
    if output_mode == "xls"
      workbook.close
    else
      file.close()
    end
  end
  return
end

# Process list of PDF files

def process_pdf_list(pdf_list,product,release,output_mode,output_file)
  found_file = 0
  pdf_list.each do |pdf_file|
    do_file = 0
    if File.exist?(pdf_file)
      if product
        if pdf_file.downcase.match(/#{product.downcase}/)
          if release
            if pdf_file.downcase.match(/#{release}/)
              do_file = 1
            end
          else
            do_file = 1
          end
        end
      else
        do_file = 1
      end
      if do_file == 1
        if $verbose == 1
          puts "Processing: "+pdf_file
        end
        found_file = 1
        txt_file   = process_pdf_file(pdf_file)
        process_txt_file(txt_file,output_mode,output_file)
      end
    end
  end
  if found_file != 1
    puts "No file found"
  end
  return
end

begin
  opt  = Getopt::Std.getopts(options)
  used = 0
  options.gsub(/:/,"").each_char do |option|
    if opt[option]
      used = 1
    end
  end
  if used == 0
    print_usage(options)
  end
rescue
  print_usage(options)
  exit
end

if opt["f"]
  input_file = opt["f"]
end

if opt["h"]
  print_usage(options)
  exit
end

if opt["V"]
  print_version()
  exit
end

if opt["v"]
  $verbose = 1
else
  $verbose = 0
end

if opt["p"]
  product = opt["p"]
else
  product = ""
end

if opt["r"]
  release = opt["r"]
else
  release = ""
end

if opt["t"]
  output_mode = "txt"
end

if opt["c"]
  output_mode = "csv"
end

if opt["x"]
  output_mode = "xls"
end

if opt["o"]
  output_file = opt["o"]
  if opt["t"]
    suffix = "txt"
  end
  if opt["x"]
    suffix = "xls"
  end
  if opt["c"]
    suffix = "csv"
  end
  if !opt["t"] and !opt["x"] and !opt["c"]
    suffix      = "txt"
    output_mode = "txt"
  end
  if !output_file.match(/#{suffix}$/)
    output_file = output_file+"."+suffix
  end
  output_dir  = Pathname.new(output_file)
  output_dir  = output_dir.dirname.to_s
  if !File.directory?(output_dir)
    File.mkpath(output_dir)
  end
else
  output_file = ""
end

if opt["l"]
  pdf_list = get_pdf_list(pdf_dir)
  pdf_list.each do |pdf_file|
    puts pdf_file
  end
end

if opt["a"] or opt["p"] or opt["r"] or opt["f"]
  pdf_list = get_pdf_list(pdf_dir)
  if input_file
    txt_file = process_pdf_file(input_file)
    process_txt_file(txt_file,output_mode,output_file)
  else
    process_pdf_list(pdf_list,product,release,output_mode,output_file)
  end
end

