
import validateurl from "../utils/validateurl.js";
import inspectUrl from "../utils/inspectUrl.js";
import generateRiskReport from "../utils/generateRiskReport.js";

async function checkUrl(req, res, dependencies = {}) {
    const url = req.body?.url;

    if (!validateurl(url)) {
        return res.status(400).json({
            valid: false,
            message: "A valid absolute HTTP or HTTPS URL is required."
        });
    }

    const inspect = dependencies.inspectUrl ?? inspectUrl;
    const generateReport = dependencies.generateRiskReport ?? generateRiskReport;

    try {
        const inspection = await inspect(url);
        return res.status(200).json(generateReport(url, inspection));
    } catch (error) {
        const reportError = error?.code
            ? error
            : Object.assign(new Error("Inspection failed"), {
                code: "INSPECTION_FAILED"
            });

        return res.status(200).json(generateReport(url, null, reportError));
    }
}

export { checkUrl };
