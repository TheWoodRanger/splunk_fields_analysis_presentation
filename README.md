# What's in my Data? Field Analysis for the Advanced Engineer - Presentation Reference Materials

- [What's in my Data? Field Analysis for the Advanced Engineer - Presentation Reference Materials](#whats-in-my-data-field-analysis-for-the-advanced-engineer---presentation-reference-materials)
  - [Session Recording + Slides](#session-recording--slides)
  - [Words of Warning!](#words-of-warning)
  - [Other Splunk .conf Presentations I recommend](#other-splunk-conf-presentations-i-recommend)
  - [Using `| loadjob` Example](#using--loadjob-example)
  - [`fieldsummary_simple`](#fieldsummary_simple)
    - [fieldsummary_simple Query String](#fieldsummary_simple-query-string)
    - [fieldsummary_simple Reference macros.conf Stanza](#fieldsummary_simple-reference-macrosconf-stanza)
  - [Fields Objects Derivation Utility Query](#fields-objects-derivation-utility-query)
  - [Configured Datamodel Fields](#configured-datamodel-fields)
  - [Usage Notes for Field Summarization Utility Queries Below](#usage-notes-for-field-summarization-utility-queries-below)
    - [Component Section Overview](#component-section-overview)
    - [Command Customizations for Summary Utilities](#command-customizations-for-summary-utilities)
  - [Field Summarization Utilities](#field-summarization-utilities)
    - [Field Summarization Utility - No Group-By](#field-summarization-utility---no-group-by)
    - [Field Summarization Utility - Single Group-by: `index`](#field-summarization-utility---single-group-by-index)
    - [Field Summarization Utility - Multiple Group-by: `index`, `sourcetype`, `source`](#field-summarization-utility---multiple-group-by-index-sourcetype-source)
      - [Field Summarization Utilities Optimization - Dynamic Filter String Example](#field-summarization-utilities-optimization---dynamic-filter-string-example)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Session Recording + Slides

Slide deck can be found under assets: [What's in my Data? Slide Deck from Bsides 21](Slide%20Deck%20-%20Field%20Analysis%20for%20the%20Advanced%20Engineer%20-%20Ryan%20Wood%20-%20Bsides%20Splunk%2021.pdf)

Session recording available on YouTube under the Splunk Community Channel:

[![Session Video Recording](http://img.youtube.com/vi/C3oN8nMVXZ8/0.jpg)](https://www.youtube.com/watch?v=C3oN8nMVXZ8)

[Youtube Link to Recording](https://www.youtube.com/watch?v=C3oN8nMVXZ8)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Words of Warning!

***I recommend you use | loadjob (or output to a lookup) when using these, as it's best to run `| map` under controlled conditions!***

***As a start: Limit number on `maxvals` setting to avoid high compute! (Default `maxvals` is 100!) Lower `maxvals` or specify more strict initial filters for your map searches if you experience long runtimes/too much compute.***

***If those optimizations don't work and you experience issues with the `| map` searches, utilize dynamic filter strategies as covered in the primary presentation materials with an example below under [Field Summarization Utilities Optimization - Dynamic Filter String Example](#field-summarization-utilities-optimization---dynamic-filter-string-example)***

Relevant reference Splunk documentation:

- [Splunk Docs on Fieldsummary Command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fieldsummary)
- [Splunk Eval Multivalue Functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Other Splunk .conf Presentations I recommend

**"I stand on the shoulders of giants."**


| Presentations                                                                                                                                                                             |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [The "Gotchas" of Splunk (Users Beware!)](https://splunkcommunity.com/wp-content/uploads/2019/11/Splunk.conf19-Gotchas.pdf)
| [Security Ninjutsu Part 4](http://conf.splunk.com/files/2017/slides/security-ninjutsu-part-four-attackers-be-gone-in-45-minutes-of-epic-spl.pdf)                                          |
| [Ninjutsu Part 6](https://www.davidveuve.com/splunk.html#ninjutsupartsix)                                                                                                                 |
| [Tricks for better SPL (SPLended Uses for SPL in SPLunk)](https://conf.splunk.com/files/2019/slides/FN1300.pdf)                                                                                                             |
| [Lesser Known Search Commands](https://conf.splunk.com/files/2019/slides/FN1061.pdf)                                                                                                      |
| [Master Joining Datasets without Using Join](https://conf.splunk.com/files/2020/slides/TRU1761C.pdf)                                                                                      |
| [Turning Security Use Cases into SPL](https://static.rainfocus.com/splunk/splunkconf18/sess/1523489574149001lr6z/finalPDF/SEC1583_TurningSecurityUseCases_Final_1538510573435001VmSg.pdf) |

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Using `| loadjob` Example

- Gather the search ID from `| addinfo` or by looking at the Job Inspector.
- Use search ID to call back to previous results to avoid need to run base search again
- Search job artifacts *do not* replicate across Search Head Cluster members by default.

![Loadjob Example Case](assets/loadjob%20example%20case.png)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## `fieldsummary_simple`

- A simple version of a fieldsummary.
- Provides a very direct “show me the fields” view that can save a lot of time and be run on the fly.

!["Simple Fieldsummary" Output](assets/Fieldsummary%20Simple%20Example%20Output.png)

**NOTE: This will return the first value found in any event, not just the first event’s values. Returns only the first value of multi-value fields.**

### fieldsummary_simple Query String

```spl
| stats first(*) AS * 
| transpose 0 column_name="field" 
| rename "row 1" as first_value
```

### fieldsummary_simple Reference macros.conf Stanza

```conf
[fieldsummary_simple]
definition = stats first(*) AS * \
| transpose 0 column_name="field" \
| rename "row 1" AS first_value
iseval = 0
```


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Fields Objects Derivation Utility Query

- Gathers field object information and combines it together into a single view
  - Calculated Fields / props.conf / transforms.conf / Aliases / Lookups
- Outputs final field set of common elements like title, field name, stanza, app, etc, then stores all conf-specific configurations/properties in the `conf_specific_properties_mv` field
- `field name` Corresponds to the specific field(s) being output by that object; for Transforms extractions there is no specific field due to being a pattern.

![Fields Objects Derivation Query Output](assets/Fields%20Objects%20Derivation%20Utility%20Output.png)

```spl
| makeresults | where 1==2 
| append 
    [| rest splunk_server=* /servicesNS/-/-/data/props/calcfields 
    | dedup id 
    | rename field.name AS field_name, eai:acl.* AS acl_* 
    | table dataSource, title, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value 
    | eval dataSource = "props-calcfields"] 
| append 
    [| rest splunk_server=* /servicesNS/-/-/data/props/extractions 
    | dedup id 
    | rename eai:acl.* AS acl_* 
    | rex field=attribute "^[^-]+-(?<field_name>.+)" 
    | table dataSource, title, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value 
    | eval dataSource = "props-extractions"] 
| append 
    [| rest splunk_server=* /servicesNS/-/-/data/props/fieldaliases 
    | dedup id 
    | foreach alias.* 
        [| eval conf_specific_properties_mv = case(
            isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), "<<FIELD>>::::" . '<<FIELD>>', 
            isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), mvappend(conf_specific_properties_mv, "<<FIELD>>::::" . '<<FIELD>>'), 
            isnotnull(conf_specific_properties_mv) AND isnull('<<FIELD>>'), conf_specific_properties_mv
            )] 
    | rename eai:acl.* AS acl_* 
    | rex field=value "\s[Aa][Ss]\s(?<field_name>.+)$" 
    | table dataSource, title, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value, conf_specific_properties_mv 
    | eval dataSource = "props-fieldaliases"] 
| append 
    [| rest splunk_server=* /servicesNS/-/-/data/props/lookups 
    | dedup id 
    | rename eai:acl.* AS acl_*, transform AS transforms_stanza 
    | fields title, type, attribute, acl_app, acl_owner, acl_sharing, value, overwrite, transforms_stanza 
    | foreach * 
        [| eval <<FIELD>> = if( match('<<FIELD>>', "."), '<<FIELD>>', null() )] 
    | eval value_modified = replace(value, "\s[Oo][Uu][Tt][Pp][Uu][Tt][Nn][Ee][Ww]\s?", " OUTPUT ") 
    | eval value_modified = if(match(value_modified, "\s[Oo][Uu][Tt][Pp][Uu][Tt]\s"), value_modified, value_modified . " OUTPUT ") 
    | eval value_modified = replace(value_modified, ",", " ") 
    | rex field=value_modified "^(?<lookup_table_name>[^\s]+)\s(?<extracted_input_segment_full>.+)\sOUTPUT\s(?<extracted_output_segment_full>.+)?" 
    | rename extracted_input_segment_full AS lookup_input_segment_full, extracted_output_segment_full AS lookup_output_segment_full 
    | makemv lookup_input_segment_full tokenizer="([^\s]+(?(?=\s[Aa][Ss]\s)(\s[Aa][Ss]\s[^\s]+)|()))" 
    | makemv lookup_output_segment_full tokenizer="([^\s]+(?(?=\s[Aa][Ss]\s)(\s[Aa][Ss]\s[^\s]+)|()))" 
    | eval lookup_output_segment_full_concat = mvjoin(lookup_output_segment_full, "::::") . "::::" 
    | rex field=lookup_output_segment_full_concat max_match=0 "(?<lookup_output_extracted_field>[^\s:]+)::::" 
    | eval field_name = if(isnotnull(lookup_output_extracted_field), mvdedup(lookup_output_extracted_field), "All Lookup Fields") 
    | foreach overwrite, transforms_stanza 
        [| eval conf_specific_properties_mv = case(
            isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), "<<FIELD>>::::" . '<<FIELD>>', 
            isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), mvappend(conf_specific_properties_mv, "<<FIELD>>::::" . '<<FIELD>>'), 
            isnotnull(conf_specific_properties_mv) AND isnull('<<FIELD>>'), conf_specific_properties_mv)
            ] 
    | foreach *_segment_full 
        [| eval conf_specific_properties_mv = case(
            isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), "<<MATCHSTR>>::::" . '<<FIELD>>', 
            isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), mvappend(conf_specific_properties_mv, "<<MATCHSTR>>::::" . '<<FIELD>>'), 
            isnotnull(conf_specific_properties_mv) AND isnull('<<FIELD>>'), conf_specific_properties_mv)
            ] 
    | eval stanza = if(match(title, " : "), replace(title, "\s:\s.+", ""), title) 
    | table dataSource, field_name, title, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value, conf_specific_properties_mv 
    | eval dataSource = "props-lookups (automatic lookups)"] 
| append 
    [| rest splunk_server=* /servicesNS/-/-/data/transforms/extractions 
    | dedup id 
    | rename eai:acl.* AS acl_*, REGEX AS value 
    | foreach * 
        [| eval <<FIELD>> = if( match('<<FIELD>>', "."), '<<FIELD>>', null() )] 
    | foreach FORMAT, CAN_OPTIMIZE, CLEAN_KEYS, DEFAULT_VALUE, SOURCE_KEY, DEST_KEY, WRITE_META, DELIMS, FIELDS, KEEP_EMPTY_VALS, LOOKAHEAD, MATCH_LIMIT, MV_ADD, REPEAT_MATCH 
        [| eval conf_specific_properties_mv = case(isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), "<<FIELD>>::::" . '<<FIELD>>', 
            isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), mvappend(conf_specific_properties_mv, "<<FIELD>>::::" . '<<FIELD>>'), 
            isnotnull(conf_specific_properties_mv) AND isnull('<<FIELD>>'), conf_specific_properties_mv)
            ] 
    | eval stanza = title 
    | table dataSource, title, stanza, acl_app, acl_owner, acl_sharing, value, conf_specific_properties_mv 
    | eval dataSource = "transforms-extractions"] 
| table dataSource, title, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value, conf_specific_properties_mv 
| eval stanza = "[" . stanza . "]" 
| rename title AS endpoint_title 
```

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Configured Datamodel Fields

- Displays all configured fields under each datamodel in the instance based on the knowledge objects that exist in the instance.
- Includes field name as well as hierarchical inheritance information for Datasets that are sub-components of datamodels.

![Configured Datamodel Fields Output](assets/Configured%20Datamodel%20Fields%20Output.png)

```spl
| datamodelsimple type="models"
| map maxsearches=1000 search="| datamodelsimple type=objects datamodel=$datamodel$ 
    | eval datamodel=\"$datamodel$\""
| map maxsearches=1000 search="| datamodelsimple type=attributes datamodel=$datamodel$ object=$object$ nodename=$lineage$ 
    | eval datamodel=\"$datamodel$\"
    | eval object=\"$object$\"
    | eval lineage=\"$lineage$\""
| eval comment = if(1==1, null(), "
These map commands have a seemingly extreme maxsearches setting, but be assured that the datamodelsimple command reads the internal configuration of the SH host and doesn't require much compute.

This search is running to compile a breakout of all datamodels, objects, and fields configured in the environment.")
| rename attribute AS field, lineage AS inheritance
```

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Usage Notes for Field Summarization Utility Queries Below

Each of the Field Summarization Utilities are split into five (5) major "component" groups of commands for ease of understanding, which are walked through in the primary presentation recording.

### Component Section Overview

1. Input data retrieval and initial `| fieldsummary` calculation on input data. *(including `| map` for GROUPBY examples)*
2. Transform `| fieldsummary` default output, add percentiles, filter minimum coverage threshold.
3. Reformat `*values*` field JSON into multi-value field, retaining value string and count ordering.
4. Format column view of `*values*` multi-value field to align individual  items across group-by’s by using dynamic whitespace insert.
    - **NOTE: You must enable "Wrap Lines" in your Format options to see the effect!**
5. Consolidate result rows where columns outside of `field` are identified as 100% equal to other rows in the dataset (BY groupby) using `checkSum` md5 hash.


![Component Overview Slides](assets/Field%20Summarization%20Component%20Overview.png)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Command Customizations for Summary Utilities

| Line                                         | Customization                                                                                                  |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| `\| where (tonumber(rtrim(diffPerc,"%")) > 10)` | Modify minimum % field coverage for a field to be included in results                                          |
| `\| fieldsummary maxvals=[int]`                 | Determines how many unique values are returned in the values field. Caution: more values means higher compute. |
| `\| map maxsearches=[int]`                      | Make sure the maxsearches for your map command is set high enough to account for the variance in your group-by |


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Field Summarization Utilities

**Note: Remove all `| eval comment` lines if desired.**

### Field Summarization Utility - No Group-By

- You can insert this after any input commands to run a summarization on that dataset. Begin at the `| fieldsummary` command point.

![Field Summarization Utility No Group-by Example Output](assets/Field%20Summarization%20Utility%20(No%20Group-by)%20Output.png)

```spl
index=_internal sourcetype=splunkd 
| eval comment = if(1==1, null(), "
START initial fieldsummary command execution.
    Note: Remove any fields desired. Modify 'maxvals' setting to desired number of output values. 'DistinctValues' calculation is up to 5x the maxvals specified.
    Fieldsummary command accepts list of fields as filter. Leave empty for '*' all fields.
") 
| fields - date_*, host, linecount, punct, splunk_server*, timestartpos, timeendpos, timestamp 
| fieldsummary maxvals=5 
| eval comment = if(1==1, null(), "
END initial fieldsummary command execution.


START fieldsummary transformations and base calculations/filtering.
") 
| eval distinctValues = case(
    (is_exact == 1), (distinct_count . " (Exact)"),
    (is_exact == 0),(distinct_count . " (Estimate)")
    ) 
| eventstats max(count) AS eventCount 
| eval diffPerc = (round(((count / eventCount) * 100),1) . "%") 
| eval comment = if(1==1, null(), "
    Note: Modify | where command below based on desired minimum % of events containing a field with values for that field to be displayed.")
| where (tonumber(rtrim(diffPerc,"%")) > 10) 
| fields - distinct_count, eventCount, is_exact, mean, max, min, stdev
| eval comment = if(1==1, null(), "
END fieldsummary transformations and base calculations/filtering.


START reformatting of 'values' JSON data into readable Multivalue field.
") 
| spath input=values path="{}.value" output="value_strings" 
| spath input=values path="{}.count" output="value_counts" 
| eval comment = if(1==1, null(), "
    Note: Since the value could be anything of any format, we wrap the value_strings field values with doublequotes through using nested multivalue functions without expanding by using ':::' as a delimiter to concat the values with doublequotes, then split them back apart.") 
| eval value_strings = split("\"" . mvjoin(value_strings, "\":::\"") . "\"", ":::") 
| eval comment = if(1==1, null(), "
    Note: Concat the two into a single MV field, formatted as 'value_strings: value_counts' using mvzip.")
| eval values = mvzip(value_strings, value_counts, ": ") 
| fields - value_counts, value_strings 
| eval comment = if(1==1, null(), "
END reformatting of 'values' JSON data into readable Multivalue field.


START column alignment formatting for values field. 
    Note: column alignment, if calculated on the aggregate dataset without GROUPBY, can result in wrapped lines if the dataset contains any fields with long values.") 
| mvexpand values 
| rex field=values "^(?<fieldValueString>\".+\"):\s(?<fieldValueCount>\d+)" 
| eventstats max(eval(len(fieldValueString))) AS max_fieldValue_len BY field 
| eval whitespaceInsertAmount = ((max_fieldValue_len + 4) - len(fieldValueString)) 
| eval values = fieldValueString . substr("                                                                                                                                                           ",1,whitespaceInsertAmount) . ":" . fieldValueCount 
| fields - whitespaceInsertAmount, max_fieldValue_len, fieldValueString, fieldValueCount 
| stats list(values) AS values, values(values) AS values_ThisMustBeSeparateToRetainOrdering, values(*) AS * BY field 
| fields - values_ThisMustBeSeparateToRetainOrdering
| eval comment = if(1==1, null(), "
END column alignment formatting for values field.


START row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash. If all the columns EXCEPT field name are equivalent, aggregate.
") 
| eval valuesHash = md5(mvjoin(values, ":::")) 
| eval checkSum = md5( count . ":::" . diffPerc . ":::" . numeric_count . ":::" . distinctValues . ":::" . valuesHash) 
| eventstats values(field) AS field BY checkSum 
| sort 0 - checkSum 
| streamstats count AS duplicateCount BY checkSum 
| where duplicateCount < 2 
| eval comment = if(1==1, null(), "
END row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash.
") 
| sort 0 - count 
| table field, count, diffPerc, numeric_count, distinctValues, values
| rename count AS "Count of Events w/ Field", diffPerc AS "Perc of Total Events w/ Field", distinctValues AS "Distinct Values", numeric_count AS "Numeric Count", values AS "Top values with count of each"
```

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Field Summarization Utility - Single Group-by: `index`

- Uses `| makeresults` to create a multivalue insert list of indexes, passes them to map command.

![Field Summarization Utility Single Group-by Example Output](assets/Field%20Summarization%20Utility%20(Single%20Group-by)%20Output.png)

```spl
| makeresults 
| fields - _time 
| eval list = "oswin*
osnix*" 
| makemv list tokenizer="([^\n]+)" 
| mvexpand list 
| rename list AS index 
| eval comment = if(1==1, null(), "
START initial fieldsummary command execution.
    Note: Remove any fields desired. Modify 'maxvals' setting to desired number of output values. 'DistinctValues' calculation is up to 5x the maxvals specified.
    Fieldsummary command accepts list of fields as filter. Leave empty for '*' all fields.
") 
| map maxsearches=10 search="search (index=\"$index$\") 
    | fields - \"date_*\", eventtype, host, linecount, punct, \"splunk_server*\", timestartpos, timeendpos, timestamp
    | fieldsummary maxvals=5
    | where (count > 0)
    | eval index = \"$index$\" " 
| eval comment = if(1==1, null(), "
END initial fieldsummary command execution via map.


START fieldsummary transformations and base calculations/filtering.
") 
| eval distinctValues = case(
    (is_exact == 1), (distinct_count . " (Exact)"),
    (is_exact == 0),(distinct_count . " (Estimate)")
    ) 
| eventstats max(count) AS eventCount BY index 
| eval diffPerc = (round(((count / eventCount) * 100),1) . "%") 
| eval comment = if(1==1, null(), "
    Note: Modify | where command below based on desired minimum % of events containing a field with values for that field to be displayed.") 
| where (tonumber(rtrim(diffPerc,"%")) > 10) 
| fields - distinct_count, eventCount, is_exact, mean, max, min, stdev
| eval comment = if(1==1, null(), "
END fieldsummary transformations and base calculations/filtering.


START reformatting of 'values' JSON data into readable Multivalue field.
")
| spath input=values path="{}.value" output="value_strings" 
| spath input=values path="{}.count" output="value_counts" 
| eval comment = if(1==1, null(), "
    Note: Since the value could be anything of any format, we wrap the value_strings field values with doublequotes through using nested multivalue functions without expanding by using ':::' as a delimiter to concat the values with doublequotes, then split them back apart.") 
| eval value_strings = split("\"" . mvjoin(value_strings, "\":::\"") . "\"", ":::") 
| eval comment = if(1==1, null(), "
    Note: Concat the two into a single MV field, formatted as 'value_strings: value_counts' using mvzip.") 
| eval values = mvzip(value_strings, value_counts, ": ") 
| fields - value_counts, value_strings 
| eval comment = if(1==1, null(), "
END reformatting of 'values' JSON data into readable Multivalue field.


START column alignment formatting for values field. 
    Note: column alignment, if calculated on the aggregate dataset without GROUPBY, can result in wrapped lines if the dataset contains any fields with long values.") 
| mvexpand values 
| rex field=values "^(?<fieldValueString>\".+\"):\s(?<fieldValueCount>\d+)" 
| eventstats max(eval(len(fieldValueString))) AS max_fieldValue_len BY field, index 
| eval whitespaceInsertAmount = ((max_fieldValue_len + 4) - len(fieldValueString))
| eval values = fieldValueString . substr("                                                                                                                                                           ",1,whitespaceInsertAmount) . ":" . fieldValueCount 
| fields - whitespaceInsertAmount, max_fieldValue_len, fieldValueString, fieldValueCount 
| stats list(values) AS values, values(values) AS values_ThisMustBeSeparateToRetainOrdering, values(*) AS * BY field, index 
| fields - values_ThisMustBeSeparateToRetainOrdering
| eval comment = if(1==1, null(), "
END column alignment formatting for values field.


START row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash. If all the columns EXCEPT field name are equivalent, aggregate.
") 
| eval valuesHash = md5(mvjoin(values, ":::")) 
| eval checkSum = md5( index . ":::" . count . ":::" . diffPerc . ":::" . numeric_count . ":::" . distinctValues . ":::" . valuesHash) 
| eventstats values(field) AS field BY checkSum 
| sort 0 - checkSum 
| streamstats count AS duplicateCount BY checkSum 
| where duplicateCount < 2 
| eval comment = if(1==1, null(), "
END row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash.
") 
| sort 0 index, -count 
| table index, field, count, diffPerc, numeric_count, distinctValues, values
| rename count AS "Count of Events w/ Field", diffPerc AS "Perc of Total Events w/ Field", distinctValues AS "Distinct Values", numeric_count AS "Numeric Count", values AS "Top values with count of each"
```


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Field Summarization Utility - Multiple Group-by: `index`, `sourcetype`, `source`

- Uses `| tstats` as a method to generate input list of index, sourcetype, source values to pass into primary map command searches.
- See [Field Summarization Utilities Optimization - Dynamic Filter String Example](#field-summarization-utilities-optimization---dynamic-filter-string-example) for example of optimizing the `| map` command execution.

![Field Summarization Utility Multiple Group-by Example Output](assets/Field%20Summarization%20Utility%20(Multiple%20Group-by)%20Output.png)

```spl
| tstats count WHERE index=* BY index, sourcetype, source
| eval comment = if(1==1, null(), "
START initial fieldsummary command execution.
    Note: Remove any fields desired. Modify 'maxvals' setting to desired number of output values. 'DistinctValues' calculation is up to 5x the maxvals specified.
    Fieldsummary command accepts list of fields as filter. Leave empty for '*' all fields.
") 
| map maxsearches=100 search="search (index=\"$index$\" sourcetype=\"$sourcetype$\" source=\"$source$\")
    | fields - \"date_*\", host, linecount, punct, \"splunk_server*\", timestartpos, timeendpos, timestamp 
    | fieldsummary maxvals=5 
    | where (count > 0)
    | eval index = \"$index$\"
    | eval sourcetype = \"$sourcetype$\"
    | eval source = \"$source$\"
    "
| eval comment = if(1==1, null(), "
END initial fieldsummary command execution via map.


START fieldsummary transformations and base calculations/filtering.
") 
| eval distinctValues = case(
    (is_exact == 1), (distinct_count . " (Exact)"),
    (is_exact == 0),(distinct_count . " (Estimate)")
    ) 
| eventstats max(count) AS eventCount BY index, sourcetype, source
| eval diffPerc = (round(((count / eventCount) * 100),1) . "%") 
| eval comment = if(1==1, null(), "
    Note: Modify | where command below based on desired minimum % of events containing a field with values for that field to be displayed.") 
| where (tonumber(rtrim(diffPerc,"%")) > 10) 
| fields - distinct_count, eventCount, is_exact, mean, max, min, stdev
| eval comment = if(1==1, null(), "
END fieldsummary transformations and base calculations/filtering.


START reformatting of 'values' JSON data into readable Multivalue field.
")
| spath input=values path="{}.value" output="value_strings" 
| spath input=values path="{}.count" output="value_counts" 
| eval comment = if(1==1, null(), "
    Note: Since the value could be anything of any format, we wrap the value_strings field values with doublequotes through using nested multivalue functions without expanding by using ':::' as a delimiter to concat the values with doublequotes, then split them back apart.") 
| eval value_strings = split("\"" . mvjoin(value_strings, "\":::\"") . "\"", ":::") 
| eval comment = if(1==1, null(), "
    Note: Concat the two into a single MV field, formatted as 'value_strings: value_counts' using mvzip.") 
| eval values = mvzip(value_strings, value_counts, ": ") 
| fields - value_counts, value_strings 
| eval comment = if(1==1, null(), "
END reformatting of 'values' JSON data into readable Multivalue field.


START column alignment formatting for values field. 
    Note: column alignment, if calculated on the aggregate dataset without GROUPBY, can result in wrapped lines if the dataset contains any fields with long values.") 
| mvexpand values 
| rex field=values "^(?<fieldValueString>\".+\"):\s(?<fieldValueCount>\d+)" 
| eventstats max(eval(len(fieldValueString))) AS max_fieldValue_len BY field, index, sourcetype, source 
| eval whitespaceInsertAmount = ((max_fieldValue_len + 4) - len(fieldValueString))
| eval values = fieldValueString . substr("                                                                                                                                                           ",1,whitespaceInsertAmount) . ":" . fieldValueCount 
| fields - whitespaceInsertAmount, max_fieldValue_len, fieldValueString, fieldValueCount 
| stats list(values) AS values, values(values) AS values_ThisMustBeSeparateToRetainOrdering, values(*) AS * BY field, index, sourcetype, source
| fields - values_ThisMustBeSeparateToRetainOrdering
| eval comment = if(1==1, null(), "
END column alignment formatting for values field.


START row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash. If all the columns EXCEPT field name are equivalent, aggregate.
") 
| eval valuesHash = md5(mvjoin(values, ":::")) 
| eval checkSum = md5( index . ":::" . sourcetype . ":::" . source . ":::" . count . ":::" . diffPerc . ":::" . numeric_count . ":::" . distinctValues . ":::" . valuesHash) 
| eventstats values(field) AS field BY checkSum 
| sort 0 - checkSum 
| streamstats count AS duplicateCount BY checkSum 
| where duplicateCount < 2 
| eval comment = if(1==1, null(), "
END row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash.
") 
| sort 0 -count 
| table index, sourcetype, source, field, count, diffPerc, numeric_count, distinctValues, values
| rename count AS "Count of Events w/ Field", diffPerc AS "Perc of Total Events w/ Field", distinctValues AS "Distinct Values", numeric_count AS "Numeric Count", values AS "Top values with count of each"
```

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Field Summarization Utilities Optimization - Dynamic Filter String Example

- Uses `specificFilterString` to pass through dynamically assigned string values to the primary `| map` search, reducing overall compute requirements to run the search.
  - Must use a subsearch to pass the string properly through to the primary map search.
- Recommendation is to optimize the primary map search input as much as you're able, and use the `| loadjob` or lookups to re-use the output without needing to run summarization search repeatedly.

![Field Summarization Optimization via Dynamic Filter String](assets/Field%20Summarization%20Optimization%20via%20Dynamic%20Filter%20String.png)

```spl
| tstats count WHERE index IN ("oswin*", "osnix*") BY index, sourcetype, source 
| eval specificFilterString = case(
    match(source, "^WinEventLog:Security"), "(TargetUserName=* AND (SubjectUserName=* OR SubjectUserSid=*))", 
    match(source, "^XmlWinEventLog:System"), "earliest=1618349400 latest=1618363811 AND (SAMAccountName=* AND signature_id=4755)", 
    match(sourcetype, "^XmlWinEventLog"), "earliest=1618349400 latest=1618363811",
    match(index, "^osnix"), "(uid IN (16255, 20755, 38169)", 
    1==1, "")
| eval comment = if( 1==1, null(), "
specificFilterString is a way to pass in conditional filter strings to the first pipe of the searches executed by the map command, allowing filtering of the data to avoid heavier impact. ")
| map maxsearches=100 search="search (index=\"$index$\" sourcetype=\"$sourcetype$\" source=\"$source$\") [| makeresults | eval search = $specificFilterString$ | return $search]
    | fields - \"date_*\", host, linecount, punct, \"splunk_server*\", timestartpos, timeendpos, timestamp 
    | fieldsummary maxvals=10 
    | where (count > 0)
    | eval index = \"$index$\"
    | eval sourcetype = \"$sourcetype$\"
    | eval source = \"$source$\"
    "
```
