"""Native Compliance & GRC routes.

This module exposes the catalog, deterministic monitoring results, findings,
evidence, risks, remediation, and audit trail through the existing Sentinel X
session and permission model.
"""
import csv
import hashlib
import io
import json
import logging
import os
from datetime import datetime

from flask import Blueprint, current_app, jsonify, render_template, request, Response
from flask_login import current_user, login_required
from sqlalchemy import or_
from werkzeug.utils import secure_filename

from models import (
    ComplianceAuditLog,
    ComplianceControl,
    ComplianceDomain,
    ComplianceEvidence,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceRequirement,
    ComplianceRemediation,
    ComplianceRisk,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceWorkbook,
    ComplianceWorkbookRecord,
    db,
)
from routes.permissions import make_blueprint_permission_check

logger = logging.getLogger(__name__)
compliance_bp = Blueprint('compliance', __name__)
compliance_bp.before_request(make_blueprint_permission_check('compliance'))


def _date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _framework_dict(item):
    controls = [
        control
        for domain in item.domains
        for requirement in domain.requirements
        for control in requirement.controls
    ]
    return {
        'id': item.id,
        'code': item.code,
        'name': item.name,
        'description': item.description,
        'version': item.version,
        'enabled': item.enabled,
        'controls': len(controls),
        'passed': sum(c.status == 'passed' for c in controls),
        'failed': sum(c.status == 'failed' for c in controls),
        'warning': sum(c.status == 'warning' for c in controls),
        'not_assessed': sum(c.status == 'not_assessed' for c in controls),
    }


def _finding_dict(item):
    return {
        'id': item.id,
        'title': item.title,
        'description': item.description,
        'source': item.source,
        'server_key': item.server_key,
        'asset': item.asset,
        'severity': item.severity,
        'risk_score': item.risk_score,
        'status': item.status,
        'verification_status': item.verification_status,
        'occurrence_count': item.occurrence_count,
        'first_detected': item.first_detected.isoformat() if item.first_detected else None,
        'last_detected': item.last_detected.isoformat() if item.last_detected else None,
        'due_date': item.due_date.isoformat() if item.due_date else None,
        'control': {
            'id': item.control.id,
            'code': item.control.code,
            'title': item.control.title,
        } if item.control else None,
        'assigned_user': item.assigned_user.username if item.assigned_user else None,
        'evidence_count': len(item.evidence),
        'remediation': item.remediation,
    }


def _get_or_create_framework(data):
    """Create or update one organization-owned framework from normalized data."""
    code = str(data.get('code', '')).strip().upper()
    name = str(data.get('name', '')).strip()
    if not code or not name:
        raise ValueError('Each framework requires code and name')
    framework = ComplianceFramework.query.filter_by(code=code).first()
    if not framework:
        framework = ComplianceFramework(code=code, name=name)
        db.session.add(framework)
    framework.name = name
    framework.description = str(data.get('description', '')).strip()
    framework.version = str(data.get('version', '1.0'))
    framework.enabled = bool(data.get('enabled', True))
    return framework


def _import_framework_payload(data):
    """Import nested JSON framework data and return creation counts."""
    data = data.get('framework', data) if isinstance(data, dict) else data
    if not isinstance(data, dict):
        raise ValueError('JSON must contain one framework object')
    framework = _get_or_create_framework(data)
    db.session.flush()
    domains_added = requirements_added = controls_added = 0
    for domain_data in data.get('domains', []):
        domain_code = str(domain_data.get('code', '')).strip().upper()
        if not domain_code:
            raise ValueError('Each domain requires code')
        domain = next((item for item in framework.domains if item.code == domain_code), None)
        if not domain:
            domain = ComplianceDomain(code=domain_code, name=str(domain_data.get('name', domain_code)))
            framework.domains.append(domain)
            domains_added += 1
        domain.name = str(domain_data.get('name', domain.name))
        domain.description = str(domain_data.get('description', '')).strip()
        for requirement_data in domain_data.get('requirements', []):
            requirement_code = str(requirement_data.get('code', '')).strip().upper()
            if not requirement_code:
                raise ValueError('Each requirement requires code')
            requirement = next((item for item in domain.requirements if item.code == requirement_code), None)
            if not requirement:
                requirement = ComplianceRequirement(
                    code=requirement_code,
                    title=str(requirement_data.get('title', requirement_code)),
                )
                domain.requirements.append(requirement)
                requirements_added += 1
            requirement.title = str(requirement_data.get('title', requirement.title))
            requirement.description = str(requirement_data.get('description', '')).strip()
            for control_data in requirement_data.get('controls', []):
                control_code = str(control_data.get('code', '')).strip().upper()
                if not control_code:
                    raise ValueError('Each control requires code')
                control = next((item for item in requirement.controls if item.code == control_code), None)
                if not control:
                    control = ComplianceControl(
                        code=control_code,
                        title=str(control_data.get('title', control_code)),
                    )
                    requirement.controls.append(control)
                    controls_added += 1
                control.title = str(control_data.get('title', control.title))
                control.description = str(control_data.get('description', '')).strip()
                control.control_type = str(control_data.get('control_type', control.control_type or 'manual')).lower()
                owner = str(control_data.get('owner', '')).strip()
                if owner:
                    control.description = (
                        f"{control.description}\nControl owner: {owner}".strip()
                    )
    return {
        'frameworks': 1,
        'domains': domains_added,
        'requirements': requirements_added,
        'controls': controls_added,
    }


@compliance_bp.route('/compliance')
@login_required
def index():
    return render_template('compliance.html')


@compliance_bp.route('/api/compliance/summary')
@login_required
def summary():
    frameworks = ComplianceFramework.query.filter_by(enabled=True).all()
    findings = ComplianceFinding.query.all()
    open_findings = [f for f in findings if f.status not in ('resolved', 'false_positive')]
    due = [f for f in open_findings if f.due_date and f.due_date < datetime.utcnow()]
    return jsonify({
        'frameworks': [_framework_dict(item) for item in frameworks],
        'controls': ComplianceControl.query.count(),
        'automated_controls': ComplianceControl.query.filter_by(control_type='automated').count(),
        'manual_controls': ComplianceControl.query.filter_by(control_type='manual').count(),
        'findings': {
            'open': len(open_findings),
            'critical': sum(f.severity == 'critical' for f in open_findings),
            'high': sum(f.severity == 'high' for f in open_findings),
            'medium': sum(f.severity == 'medium' for f in open_findings),
            'low': sum(f.severity == 'low' for f in open_findings),
            'overdue': len(due),
        },
        'evidence': {
            'fresh': ComplianceEvidence.query.filter_by(status='fresh').count(),
            'expiring': ComplianceEvidence.query.filter_by(status='expiring').count(),
            'expired': ComplianceEvidence.query.filter_by(status='expired').count(),
        },
        'risks': {
            'open': ComplianceRisk.query.filter_by(status='open').count(),
            'critical': sum((risk.inherent_risk or 0) >= 16 for risk in ComplianceRisk.query.filter_by(status='open')),
        },
    })


@compliance_bp.route('/api/compliance/frameworks')
@login_required
def frameworks():
    return jsonify([_framework_dict(item) for item in ComplianceFramework.query.order_by(ComplianceFramework.name).all()])


@compliance_bp.route('/api/compliance/controls')
@login_required
def controls():
    query = ComplianceControl.query
    framework_id = request.args.get('framework_id', type=int)
    if framework_id:
        query = query.join(ComplianceControl.requirement).join(
            ComplianceControl.requirement.property.mapper.class_.domain
        ).filter_by(framework_id=framework_id)
    items = query.order_by(ComplianceControl.code).all()
    return jsonify([{
        'id': item.id,
        'code': item.code,
        'title': item.title,
        'description': item.description,
        'control_type': item.control_type,
        'status': item.status,
        'framework': item.requirement.domain.framework.name,
    } for item in items])


@compliance_bp.route('/api/compliance/controls/<int:control_id>')
@login_required
def control_detail(control_id):
    item = ComplianceControl.query.get_or_404(control_id)
    records = ComplianceWorkbookRecord.query.filter_by(control_id=item.id).order_by(
        ComplianceWorkbookRecord.sheet_name,
        ComplianceWorkbookRecord.id,
    ).all()
    return jsonify({
        'id': item.id,
        'code': item.code,
        'title': item.title,
        'description': item.description,
        'control_type': item.control_type,
        'status': item.status,
        'framework': item.requirement.domain.framework.name,
        'domain': item.requirement.domain.name,
        'requirement': item.requirement.title,
        'evidence_count': ComplianceEvidence.query.filter_by(control_id=item.id).count(),
        'workbook_records': [{
            'id': record.id,
            'sheet_name': record.sheet_name,
            'record_type': record.record_type,
            'title': record.title,
            'status': record.status,
            'data': json.loads(record.data_json),
        } for record in records],
    })


@compliance_bp.route('/api/compliance/controls', methods=['POST'])
@login_required
def create_control():
    if not current_user.is_admin():
        return jsonify({'error': 'Administrator privileges required'}), 403
    payload = request.get_json(silent=True) or {}
    requirement = ComplianceRequirement.query.get(payload.get('requirement_id'))
    code = str(payload.get('code', '')).strip().upper()
    title = str(payload.get('title', '')).strip()
    if not requirement or not code or not title:
        return jsonify({'error': 'requirement_id, code, and title are required'}), 400
    if ComplianceControl.query.filter_by(code=code).first():
        return jsonify({'error': 'Control code already exists'}), 409
    control = ComplianceControl(
        requirement_id=requirement.id,
        code=code,
        title=title,
        description=str(payload.get('description', '')).strip(),
        control_type=str(payload.get('control_type', 'manual')).lower(),
    )
    db.session.add(control)
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='control_created',
        object_type='control',
        new_value=json.dumps({'code': code, 'requirement_id': requirement.id}),
    ))
    db.session.commit()
    return jsonify({'id': control.id, 'code': control.code}), 201


@compliance_bp.route('/api/compliance/import-template')
@login_required
def import_template():
    content = (
        'framework_code,framework_name,framework_version,framework_description,'
        'domain_code,domain_name,requirement_code,requirement_title,'
        'control_code,control_title,control_description,control_type,owner\n'
        'ORG,My Organization Framework,1.0,Our security requirements,'
        'ORG-D01,Access Management,ORG-R01,User access is reviewed,'
        'ORG-C01,Quarterly access review,Review privileged access quarterly,manual,Security\n'
    )
    return Response(content, mimetype='text/csv', headers={
        'Content-Disposition': 'attachment; filename=sentinel-compliance-template.csv',
    })


@compliance_bp.route('/api/compliance/import', methods=['POST'])
@login_required
def import_catalog():
    if not current_user.is_admin():
        return jsonify({'error': 'Administrator privileges required'}), 403
    uploaded = request.files.get('file')
    if not uploaded or not uploaded.filename:
        return jsonify({'error': 'Upload a JSON or CSV framework file'}), 400
    try:
        extension = os.path.splitext(uploaded.filename.lower())[1]
        if extension == '.json':
            counts = _import_framework_payload(json.load(uploaded))
        elif extension == '.csv':
            rows = list(csv.DictReader(io.TextIOWrapper(uploaded.stream, encoding='utf-8-sig')))
            if not rows:
                raise ValueError('CSV has no data rows')
            first = rows[0]
            framework_data = {
                'code': first.get('framework_code'),
                'name': first.get('framework_name'),
                'version': first.get('framework_version') or '1.0',
                'description': first.get('framework_description', ''),
                'domains': [],
            }
            domain_map = {}
            requirement_map = {}
            for row in rows:
                domain_code = str(row.get('domain_code', '')).strip().upper()
                requirement_code = str(row.get('requirement_code', '')).strip().upper()
                domain = domain_map.setdefault(domain_code, {
                    'code': domain_code, 'name': row.get('domain_name') or domain_code,
                    'requirements': [],
                })
                requirement = requirement_map.setdefault((domain_code, requirement_code), {
                    'code': requirement_code, 'title': row.get('requirement_title') or requirement_code,
                    'controls': [],
                })
                if requirement not in domain['requirements']:
                    domain['requirements'].append(requirement)
                requirement['controls'].append({
                    'code': row.get('control_code'),
                    'title': row.get('control_title'),
                    'description': row.get('control_description', ''),
                    'control_type': row.get('control_type') or 'manual',
                    'owner': row.get('owner', ''),
                })
            framework_data['domains'] = list(domain_map.values())
            counts = _import_framework_payload(framework_data)
        else:
            return jsonify({'error': 'Only .json and .csv files are supported'}), 400
        db.session.add(ComplianceAuditLog(
            user_id=current_user.id,
            action='catalog_imported',
            object_type='framework',
            new_value=json.dumps({'filename': secure_filename(uploaded.filename), 'counts': counts}),
        ))
        db.session.commit()
        return jsonify({'message': 'Catalog imported successfully', 'counts': counts})
    except Exception as exc:
        db.session.rollback()
        logger.exception('Compliance catalog import failed')
        return jsonify({'error': str(exc)}), 400


@compliance_bp.route('/api/compliance/workbooks')
@login_required
def workbooks():
    items = ComplianceWorkbook.query.order_by(ComplianceWorkbook.imported_at.desc()).all()
    return jsonify([{
        'id': item.id,
        'name': item.name,
        'filename': item.original_filename,
        'framework_id': item.framework_id,
        'imported_at': item.imported_at.isoformat(),
        'active': item.active,
        'sheets': sorted({record.sheet_name for record in item.records}),
        'records': len(item.records),
        'controls': len({record.control_id for record in item.records if record.control_id}),
    } for item in items])


@compliance_bp.route('/api/compliance/workbooks/import', methods=['POST'])
@login_required
def import_workbook():
    if not current_user.is_admin():
        return jsonify({'error': 'Administrator privileges required'}), 403
    uploaded = request.files.get('file')
    if not uploaded or not uploaded.filename.lower().endswith(('.xlsx', '.xlsm')):
        return jsonify({'error': 'Upload an .xlsx or .xlsm SOC 2 workbook'}), 400
    try:
        from compliance_engine import import_soc2_workbook
        payload = import_soc2_workbook(uploaded.read(), secure_filename(uploaded.filename), current_user.id)
        return jsonify(payload), 201 if not payload.get('duplicate') else 200
    except Exception as exc:
        db.session.rollback()
        logger.exception('SOC 2 workbook import failed')
        return jsonify({'error': str(exc)}), 400


@compliance_bp.route('/api/compliance/workbooks/<int:workbook_id>/sheets')
@login_required
def workbook_sheets(workbook_id):
    workbook = ComplianceWorkbook.query.get_or_404(workbook_id)
    rows = db.session.query(
        ComplianceWorkbookRecord.sheet_name,
        db.func.count(ComplianceWorkbookRecord.id),
    ).filter_by(workbook_id=workbook.id).group_by(
        ComplianceWorkbookRecord.sheet_name
    ).order_by(ComplianceWorkbookRecord.sheet_name).all()
    return jsonify([{'name': name, 'records': count} for name, count in rows])


@compliance_bp.route('/api/compliance/workbooks/<int:workbook_id>/records')
@login_required
def workbook_records(workbook_id):
    workbook = ComplianceWorkbook.query.get_or_404(workbook_id)
    query = ComplianceWorkbookRecord.query.filter_by(workbook_id=workbook.id)
    sheet = request.args.get('sheet')
    record_type = request.args.get('record_type')
    search = request.args.get('search', '').strip()
    if sheet:
        query = query.filter_by(sheet_name=sheet)
    if record_type:
        query = query.filter_by(record_type=record_type)
    if search:
        query = query.filter(
            or_(
                ComplianceWorkbookRecord.record_key.ilike(f'%{search}%'),
                ComplianceWorkbookRecord.title.ilike(f'%{search}%'),
            )
        )
    items = query.order_by(ComplianceWorkbookRecord.id).limit(1000).all()
    return jsonify([{
        'id': item.id,
        'sheet_name': item.sheet_name,
        'record_type': item.record_type,
        'record_key': item.record_key,
        'title': item.title,
        'status': item.status,
        'control_id': item.control_id,
        'control_code': item.control.code if item.control else None,
        'data': json.loads(item.data_json),
    } for item in items])


@compliance_bp.route('/api/compliance/workbook-records/<int:record_id>')
@login_required
def workbook_record_detail(record_id):
    item = ComplianceWorkbookRecord.query.get_or_404(record_id)
    return jsonify({
        'id': item.id,
        'workbook_id': item.workbook_id,
        'sheet_name': item.sheet_name,
        'record_type': item.record_type,
        'record_key': item.record_key,
        'title': item.title,
        'status': item.status,
        'control_id': item.control_id,
        'control_code': item.control.code if item.control else None,
        'data': json.loads(item.data_json),
    })


@compliance_bp.route('/api/compliance/rules')
@login_required
def rules():
    items = ComplianceRule.query.order_by(ComplianceRule.name).all()
    return jsonify([{
        'id': item.id,
        'name': item.name,
        'source': item.source,
        'severity': item.severity,
        'enabled': item.enabled,
        'schedule': item.schedule,
        'condition': item.get_condition(),
        'controls': [link.control.code for link in item.controls if link.control],
    } for item in items])


@compliance_bp.route('/api/compliance/rules', methods=['POST'])
@login_required
def create_rule():
    if not current_user.is_admin():
        return jsonify({'error': 'Administrator privileges required'}), 403
    payload = request.get_json(silent=True) or {}
    name = str(payload.get('name', '')).strip()
    condition = payload.get('condition')
    if not name or not isinstance(condition, dict):
        return jsonify({'error': 'Rule name and a JSON condition are required'}), 400
    rule = ComplianceRule(
        name=name,
        source=str(payload.get('source', 'wazuh')).lower(),
        severity=str(payload.get('severity', 'medium')).lower(),
        schedule=str(payload.get('schedule', 'hourly')).lower(),
        created_by=current_user.id,
    )
    rule.set_condition(condition)
    db.session.add(rule)
    db.session.flush()
    control_ids = payload.get('control_ids') or []
    controls = ComplianceControl.query.filter(ComplianceControl.id.in_(control_ids)).all() if control_ids else []
    for control in controls:
        db.session.add(ComplianceRuleControl(rule_id=rule.id, control_id=control.id))
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='rule_created',
        object_type='rule',
        object_id=str(rule.id),
        new_value=json.dumps({'name': name, 'controls': [c.id for c in controls]}),
    ))
    db.session.commit()
    return jsonify({'id': rule.id, 'name': rule.name, 'controls': [c.id for c in controls]}), 201


@compliance_bp.route('/api/compliance/findings')
@login_required
def findings():
    query = ComplianceFinding.query
    status = request.args.get('status')
    severity = request.args.get('severity')
    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)
    items = query.order_by(ComplianceFinding.last_detected.desc()).limit(500).all()
    return jsonify([_finding_dict(item) for item in items])


@compliance_bp.route('/api/compliance/findings/<int:finding_id>')
@login_required
def finding_detail(finding_id):
    item = ComplianceFinding.query.get_or_404(finding_id)
    data = _finding_dict(item)
    data['evidence'] = [{
        'id': evidence.id,
        'source': evidence.source,
        'server_key': evidence.server_key,
        'source_index': evidence.source_index,
        'source_document_id': evidence.source_document_id,
        'sha256': evidence.sha256,
        'collected_at': evidence.collected_at.isoformat(),
        'status': evidence.status,
        'snapshot': json.loads(evidence.snapshot_json),
    } for evidence in item.evidence]
    data['risks'] = [{
        'id': risk.id,
        'name': risk.name,
        'likelihood': risk.likelihood,
        'impact': risk.impact,
        'inherent_risk': risk.inherent_risk,
        'residual_risk': risk.residual_risk,
        'treatment': risk.treatment,
        'status': risk.status,
    } for risk in item.risks]
    data['remediations'] = [{
        'id': remediation.id,
        'title': remediation.title,
        'recommendation': remediation.recommendation,
        'status': remediation.status,
        'due_date': remediation.due_date.isoformat() if remediation.due_date else None,
    } for remediation in item.remediations]
    return jsonify(data)


@compliance_bp.route('/api/compliance/evidence', methods=['GET'])
@login_required
def evidence_list():
    query = ComplianceEvidence.query.order_by(ComplianceEvidence.collected_at.desc())
    control_id = request.args.get('control_id', type=int)
    finding_id = request.args.get('finding_id', type=int)
    if control_id:
        query = query.filter_by(control_id=control_id)
    if finding_id:
        query = query.filter_by(finding_id=finding_id)
    return jsonify([{
        'id': item.id,
        'source': item.source,
        'finding_id': item.finding_id,
        'control_id': item.control_id,
        'source_document_id': item.source_document_id,
        'sha256': item.sha256,
        'collected_at': item.collected_at.isoformat(),
        'status': item.status,
        'snapshot': json.loads(item.snapshot_json),
    } for item in query.limit(500).all()])


@compliance_bp.route('/api/compliance/evidence', methods=['POST'])
@login_required
def upload_evidence():
    """Store organization evidence with provenance and a tamper-evident hash."""
    uploaded = request.files.get('file')
    if not uploaded or not uploaded.filename:
        return jsonify({'error': 'Choose an evidence file to upload'}), 400
    control_id = request.form.get('control_id', type=int)
    finding_id = request.form.get('finding_id', type=int)
    if not control_id and not finding_id:
        return jsonify({'error': 'Link evidence to a control or finding'}), 400
    control = ComplianceControl.query.get(control_id) if control_id else None
    finding = ComplianceFinding.query.get(finding_id) if finding_id else None
    if control_id and not control:
        return jsonify({'error': 'Control not found'}), 404
    if finding_id and not finding:
        return jsonify({'error': 'Finding not found'}), 404
    payload = uploaded.read()
    if len(payload) > 10 * 1024 * 1024:
        return jsonify({'error': 'Evidence files are limited to 10 MB'}), 413
    filename = secure_filename(uploaded.filename) or 'evidence.bin'
    digest = hashlib.sha256(payload).hexdigest()
    evidence_dir = os.path.join(current_app.instance_path, 'compliance_evidence')
    os.makedirs(evidence_dir, exist_ok=True)
    stored_name = f'{digest[:16]}-{filename}'
    stored_path = os.path.join(evidence_dir, stored_name)
    with open(stored_path, 'wb') as evidence_file:
        evidence_file.write(payload)
    snapshot = {
        'filename': filename,
        'stored_name': stored_name,
        'size_bytes': len(payload),
        'sha256': digest,
        'title': request.form.get('title', filename),
        'notes': request.form.get('notes', ''),
        'uploaded_by': current_user.username,
    }
    existing = ComplianceEvidence.query.filter_by(sha256=digest, control_id=control_id, finding_id=finding_id).first()
    if existing:
        return jsonify({'id': existing.id, 'message': 'This evidence file is already recorded'}), 200
    evidence = ComplianceEvidence(
        finding_id=finding_id,
        control_id=control_id,
        source='manual',
        snapshot_json=json.dumps(snapshot),
        sha256=digest,
        freshness_days=int(request.form.get('freshness_days', 30)),
        status='fresh',
    )
    db.session.add(evidence)
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='evidence_uploaded',
        object_type='evidence',
        new_value=json.dumps({'filename': filename, 'sha256': digest, 'control_id': control_id, 'finding_id': finding_id}),
    ))
    db.session.commit()
    return jsonify({'id': evidence.id, 'sha256': digest, 'message': 'Evidence uploaded and recorded'}), 201


@compliance_bp.route('/api/compliance/evaluate', methods=['POST'])
@login_required
def evaluate():
    payload = request.get_json(silent=True) or {}
    server_key = payload.get('server_key', 'primary')
    try:
        from compliance_engine import evaluate_wazuh
        result = evaluate_wazuh(
            server_key=server_key,
            hours=int(payload.get('hours', 24)),
            limit=int(payload.get('limit', 1000)),
        )
        ComplianceAuditLog.query  # ensure model is available for audit trail readers
        db.session.add(ComplianceAuditLog(
            user_id=current_user.id,
            action='evaluate',
            object_type='compliance',
            object_id=server_key,
            new_value=json.dumps(result),
        ))
        db.session.commit()
        return jsonify(result)
    except Exception as exc:
        db.session.rollback()
        logger.exception('Compliance evaluation failed')
        return jsonify({'error': str(exc)}), 502


@compliance_bp.route('/api/compliance/findings/<int:finding_id>/status', methods=['POST'])
@login_required
def update_finding_status(finding_id):
    item = ComplianceFinding.query.get_or_404(finding_id)
    payload = request.get_json(silent=True) or {}
    status = str(payload.get('status', '')).lower().strip()
    allowed = {'open', 'acknowledged', 'in_progress', 'pending_verification',
               'resolved', 'accepted_risk', 'false_positive', 'exception', 'reopened'}
    if status not in allowed:
        return jsonify({'error': 'Unsupported finding status'}), 400
    if status == 'resolved' and item.status not in ('pending_verification', 'resolved'):
        return jsonify({'error': 'Findings must go through pending_verification before resolved'}), 409
    old = item.status
    item.status = status
    item.verification_status = 'passed' if status == 'resolved' else item.verification_status
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='status_changed',
        object_type='finding',
        object_id=str(item.id),
        old_value=json.dumps({'status': old}),
        new_value=json.dumps({'status': status}),
    ))
    db.session.commit()
    return jsonify(_finding_dict(item))


@compliance_bp.route('/api/compliance/findings/<int:finding_id>/assign', methods=['POST'])
@login_required
def assign_finding(finding_id):
    item = ComplianceFinding.query.get_or_404(finding_id)
    payload = request.get_json(silent=True) or {}
    assigned_user_id = payload.get('assigned_user_id')
    if assigned_user_id is None:
        return jsonify({'error': 'assigned_user_id is required'}), 400
    from models import User
    assignee = User.query.get(assigned_user_id)
    if not assignee:
        return jsonify({'error': 'Assigned user not found'}), 404
    previous = item.assigned_user_id
    item.assigned_user_id = assignee.id
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='finding_assigned',
        object_type='finding',
        object_id=str(item.id),
        old_value=json.dumps({'assigned_user_id': previous}),
        new_value=json.dumps({'assigned_user_id': assignee.id}),
    ))
    db.session.commit()
    return jsonify(_finding_dict(item))


@compliance_bp.route('/api/compliance/findings/<int:finding_id>/remediation', methods=['POST'])
@login_required
def add_remediation(finding_id):
    item = ComplianceFinding.query.get_or_404(finding_id)
    payload = request.get_json(silent=True) or {}
    title = str(payload.get('title', '')).strip()
    if not title:
        return jsonify({'error': 'A remediation title is required'}), 400
    remediation = ComplianceRemediation(
        finding_id=item.id,
        title=title,
        recommendation=str(payload.get('recommendation', '')).strip(),
        owner_id=payload.get('owner_id') or current_user.id,
        due_date=_date(payload.get('due_date')),
        status='open',
    )
    item.status = 'in_progress'
    db.session.add(remediation)
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='remediation_created',
        object_type='finding',
        object_id=str(item.id),
        new_value=json.dumps({'title': title}),
    ))
    db.session.commit()
    return jsonify({'id': remediation.id, 'status': remediation.status}), 201


@compliance_bp.route('/api/compliance/risks', methods=['POST'])
@login_required
def create_risk():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get('name', '')).strip()
    if not name:
        return jsonify({'error': 'A risk name is required'}), 400
    likelihood = max(1, min(int(payload.get('likelihood', 3)), 5))
    impact = max(1, min(int(payload.get('impact', 3)), 5))
    risk = ComplianceRisk(
        name=name,
        description=str(payload.get('description', '')).strip(),
        finding_id=payload.get('finding_id'),
        likelihood=likelihood,
        impact=impact,
        inherent_risk=likelihood * impact,
        residual_risk=likelihood * impact,
        owner_id=payload.get('owner_id') or current_user.id,
        treatment=payload.get('treatment', 'mitigate'),
        due_date=_date(payload.get('due_date')),
    )
    db.session.add(risk)
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='risk_created',
        object_type='risk',
        new_value=json.dumps({'name': name}),
    ))
    db.session.commit()
    return jsonify({'id': risk.id, 'inherent_risk': risk.inherent_risk}), 201


@compliance_bp.route('/api/compliance/frameworks', methods=['POST'])
@login_required
def create_framework():
    if not current_user.is_admin():
        return jsonify({'error': 'Administrator privileges required'}), 403
    payload = request.get_json(silent=True) or {}
    code = str(payload.get('code', '')).strip().upper()
    name = str(payload.get('name', '')).strip()
    if not code or not name:
        return jsonify({'error': 'Framework code and name are required'}), 400
    if ComplianceFramework.query.filter_by(code=code).first():
        return jsonify({'error': 'Framework code already exists'}), 409
    framework = ComplianceFramework(
        code=code,
        name=name,
        description=str(payload.get('description', '')).strip(),
        version=str(payload.get('version', '1.0')),
    )
    db.session.add(framework)
    db.session.add(ComplianceAuditLog(
        user_id=current_user.id,
        action='framework_created',
        object_type='framework',
        new_value=json.dumps({'code': code, 'name': name}),
    ))
    db.session.commit()
    return jsonify({'id': framework.id, 'code': framework.code}), 201


@compliance_bp.route('/api/compliance/audit-log')
@login_required
def audit_log():
    items = ComplianceAuditLog.query.order_by(ComplianceAuditLog.created_at.desc()).limit(200).all()
    return jsonify([{
        'id': item.id,
        'action': item.action,
        'object_type': item.object_type,
        'object_id': item.object_id,
        'user': item.user.username if item.user else 'system',
        'created_at': item.created_at.isoformat(),
    } for item in items])